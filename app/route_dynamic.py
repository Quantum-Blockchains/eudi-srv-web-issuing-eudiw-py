# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The Dynamic Issuer Web service is a component of the Dynamic Provider backend.
Its main goal is to issue the credentials in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This route_dynamic.py file is the blueprint for the route /dynamic of the PID Issuer Web service.
"""
from datetime import datetime, timezone
from datetime import date
from datetime import timedelta
from difflib import SequenceMatcher
from email.message import EmailMessage
import json
import base64
import random
import re
import smtplib
from urllib.parse import urlencode
from uuid import uuid4
from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    session,
)
from flask_api import status
from flask_cors import CORS
import requests

from boot_validate import (
    validate_mandatory_args,
)

from app_config.config_service import ConfService as cfgserv
from app_config.config_countries import ConfCountries as cfgcountries, ConfFrontend
from redirect_func import url_get
from app.redirect_func import post_redirect_with_payload
from misc import (
    convert_png_to_jpeg,
    credential_error_resp,
    getAttributesForm,
    getAttributesForm2,
    calculate_age,
    vct2doctype,
    generate_unique_id,
    vct2id,
    scope2details,
)
from dynamic_func import dynamic_formatter
from app import oidc_metadata
from app import session_manager

# /pid blueprint
dynamic = Blueprint("dynamic", __name__, url_prefix="/dynamic")
CORS(dynamic)  # enable CORS on the blue print


def _get_target_frontend_url(frontend_id):
    return ConfFrontend.registered_frontends[frontend_id]["url"]


def _resolve_display_name(credential):
    if "credential_metadata" in credential:
        return credential["credential_metadata"]["display"][0]["name"]
    return credential["display"][0]["name"]


def _resolve_claims(credential):
    if "credential_metadata" in credential:
        return credential["credential_metadata"]["claims"]
    return credential["claims"]


def _get_auth_method_flags(credentials_requested):
    supported_credentials = cfgserv.auth_method_supported_credencials

    pid_auth = all(
        credential in supported_credentials["PID_login"]
        for credential in credentials_requested
    )
    country_selection = all(
        credential in supported_credentials["country_selection"]
        for credential in credentials_requested
    )
    lei_lookup = all(
        credential in supported_credentials["lei_lookup"]
        for credential in credentials_requested
    )

    return pid_auth, country_selection, lei_lookup


def _render_auth_method_selection(current_session, error=""):
    pid_auth, country_selection, lei_lookup = _get_auth_method_flags(
        current_session.credentials_requested
    )

    return post_redirect_with_payload(
        target_url=f"{_get_target_frontend_url(current_session.frontend_id)}/display_auth_method",
        data_payload={
            "pid_auth": pid_auth,
            "country_selection": country_selection,
            "lei_lookup": lei_lookup,
            "redirect_url": cfgserv.service_url,
            "session_id": current_session.session_id,
            "error": error,
        },
    )


def _render_lei_form(current_session, error="", lei=""):
    return post_redirect_with_payload(
        target_url=f"{_get_target_frontend_url(current_session.frontend_id)}/display_lei",
        data_payload={
            "redirect_url": f"{cfgserv.service_url}dynamic/lei",
            "error": error,
            "lei": lei,
            "session_id": current_session.session_id,
        },
    )


PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "yandex.com",
    "zoho.com",
}


def _normalize_company_text(value):
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _extract_domain_root(domain):
    parts = [part for part in (domain or "").lower().split(".") if part]
    if not parts:
        return ""

    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {
        "ac",
        "co",
        "com",
        "gov",
        "net",
        "org",
    }:
        return parts[-3]

    if len(parts) >= 2:
        return parts[-2]

    return parts[0]


def _company_tokens(company_name):
    ignored_tokens = {
        "and",
        "company",
        "corp",
        "corporation",
        "gmbh",
        "group",
        "holding",
        "inc",
        "limited",
        "llc",
        "ltd",
        "plc",
        "sa",
        "sas",
        "spa",
        "the",
    }
    return [
        token
        for token in re.findall(r"[a-z0-9]+", (company_name or "").lower())
        if len(token) >= 3 and token not in ignored_tokens
    ]


def _email_domain_matches_company(company_name, email_domain):
    domain_root = _extract_domain_root(email_domain)
    domain_norm = _normalize_company_text(domain_root)
    company_norm = _normalize_company_text(company_name)

    if not domain_norm or not company_norm:
        return False

    if email_domain.lower() in PUBLIC_EMAIL_DOMAINS:
        return False

    if domain_norm in company_norm or company_norm in domain_norm:
        return True

    company_tokens = _company_tokens(company_name)
    if any(token in domain_norm or domain_norm in token for token in company_tokens):
        return True

    comparison_candidates = [company_norm] + company_tokens
    return any(
        SequenceMatcher(None, domain_norm, candidate).ratio() >= 0.75
        for candidate in comparison_candidates
        if candidate
    )


def _validate_employee_email(employee_email, company_name):
    normalized_email = (employee_email or "").strip().lower()

    if not normalized_email:
        return "Employee email is required."

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized_email):
        return "Enter a valid employee email address."

    email_domain = normalized_email.split("@", 1)[1]
    if email_domain in PUBLIC_EMAIL_DOMAINS:
        return "Use your company email address, not a public mailbox."

    if not _email_domain_matches_company(company_name=company_name, email_domain=email_domain):
        return "Email domain must match the company name from the LEI record."

    return ""


def _build_authorization_payload(
    current_session,
    presentation_data,
    error="",
    employee_email="",
    authorization_requires_email=False,
    otp_sent=False,
    otp_code="",
    info_message="",
):
    company_name = ""
    if current_session.user_data:
        company_name = current_session.user_data.get("legal_name", "")

    return {
        "presentation_data": presentation_data,
        "redirect_url": f"{cfgserv.service_url}dynamic/redirect_wallet",
        "session_id": current_session.session_id,
        "error": error,
        "work_email": employee_email,
        "authorization_requires_email": authorization_requires_email,
        "company_name": company_name,
        "otp_sent": otp_sent,
        "otp_code": otp_code,
        "info_message": info_message,
    }


def _send_otp_email(recipient_email, otp_code, company_name):
    if not (
        cfgserv.otp_email_host
        and cfgserv.otp_email_from_address
        and cfgserv.otp_email_username
        and cfgserv.otp_email_password
    ):
        cfgserv.app_logger.warning(
            "OTP email delivery is not configured. Generated OTP for %s (%s): %s",
            recipient_email,
            company_name,
            otp_code,
        )
        return (
            False,
            "OTP email delivery is not configured on the server.",
        )

    message = EmailMessage()
    message["Subject"] = "Your verification code"
    message["From"] = cfgserv.otp_email_from
    message["To"] = recipient_email
    message.set_content(
        "\n".join(
            [
                "Your one-time verification code is:",
                "",
                str(otp_code),
                "",
                f"Company: {company_name}" if company_name else "",
                "If you did not request this code, ignore this email.",
            ]
        ).strip()
    )

    try:
        with smtplib.SMTP(cfgserv.otp_email_host, cfgserv.otp_email_port, timeout=20) as smtp:
            if cfgserv.otp_email_use_tls:
                smtp.starttls()
            smtp.login(cfgserv.otp_email_username, cfgserv.otp_email_password)
            smtp.send_message(message)
    except Exception as exc:
        cfgserv.app_logger.error(
            "Failed to send OTP email to %s: %s",
            recipient_email,
            str(exc),
        )
        return False, "Failed to send the OTP email. Try again."

    cfgserv.app_logger.info("OTP email sent to %s", recipient_email)
    return True, ""


def _render_lei_authorization(
    current_session,
    error="",
    employee_email="",
    otp_sent=False,
    otp_code="",
    info_message="",
):
    presentation_data = _build_presentation_data(cleaned_data=current_session.user_data or {})
    return post_redirect_with_payload(
        target_url=f"{_get_target_frontend_url(current_session.frontend_id)}/display_authorization",
        data_payload=_build_authorization_payload(
            current_session=current_session,
            presentation_data=presentation_data,
            error=error,
            employee_email=employee_email,
            authorization_requires_email=True,
            otp_sent=otp_sent,
            otp_code=otp_code,
            info_message=info_message,
        ),
    )


def _requested_credentials_from_session():
    authorization_params = session.get("authorization_params", {})
    authorization_details = []

    if "authorization_details" in authorization_params:
        authorization_details.extend(
            json.loads(authorization_params["authorization_details"])
        )
    if "scope" in authorization_params:
        authorization_details.extend(scope2details(authorization_params["scope"]))

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            cred_id = cred["credential_configuration_id"]
        elif "vct" in cred:
            cred_id = vct2id(cred["vct"])
        else:
            continue

        if cred_id not in credentials_requested:
            credentials_requested.append(cred_id)

    return credentials_requested


def _fetch_lei_data(lei):
    url = f"{cfgserv.lei_api_base_url}/{lei}.jsonld"
    
    cfgserv.app_logger.info(f"LEI lookup: Fetching from {url}")

    headers = {
        "User-Agent": "Mozilla/5.0 (EUDI-Issuer/1.0; +https://github.com/eu-digital-identity-wallet)",
        "Accept": "application/ld+json, application/json",
    }

    cfgserv.app_logger.debug(f"LEI lookup: Request headers: {headers}")

    try:
        response = requests.get(url, headers=headers, timeout=10)
        cfgserv.app_logger.debug(f"LEI lookup: Response status={response.status_code}, headers={dict(response.headers)}")
    except requests.RequestException as e:
        cfgserv.app_logger.error(f"LEI lookup: Network error for {lei}: {str(e)}")
        return None, "LEI lookup failed"

    if response.status_code != 200:
        cfgserv.app_logger.warning(f"LEI lookup: HTTP {response.status_code} for {lei}, response body (first 200 chars): {response.text[:200]}")
        return None, "LEI record was not found (lei.info)"

    try:
        json_data = response.json()
    except (ValueError, TypeError) as e:
        cfgserv.app_logger.error(f"LEI lookup: JSON parse error for {lei}: {str(e)}")
        return None, "LEI response could not be parsed"

    record = None
    if isinstance(json_data, dict) and "data" in json_data:
        record = json_data.get("data", {}).get("attributes", {}).get("entity")
    elif isinstance(json_data, list):
        record = next(
            (
                item
                for item in json_data
                if isinstance(item, dict)
                and "LegalEntity" in str(item.get("@type", ""))
            ),
            None,
        )

    if not isinstance(record, dict):
        cfgserv.app_logger.error(f"LEI lookup: No LegalEntity record found in response for {lei}")
        return None, "LEI record could not be parsed (lei.info jsonld)"

    cfgserv.app_logger.debug(f"LEI lookup: Parsed LegalEntity record for {lei}")

    # Handle lei.info JSON-LD property names first, then GLEIF names as fallback
    legal_address = record.get("l1:legalAddress", record.get("legalAddress", {}))
    legal_address_parts = [
        record.get("l1:streetAddress", legal_address.get("streetAddress")),
        record.get("l1:city", legal_address.get("city")),
        record.get("l1:region", legal_address.get("region")),
        record.get("l1:postalCode", legal_address.get("postalCode")),
        record.get("l1:country", legal_address.get("country")),
    ]
    legal_address_value = ", ".join([part for part in legal_address_parts if part])

    raw_jurisdiction = record.get("l1:legalJurisdiction", record.get("legalJurisdiction", ""))
    if isinstance(raw_jurisdiction, dict):
        legal_jurisdiction = (
            raw_jurisdiction.get("id")
            or raw_jurisdiction.get("value")
            or raw_jurisdiction.get("code")
            or ""
        )
    elif isinstance(raw_jurisdiction, list) and raw_jurisdiction:
        legal_jurisdiction = raw_jurisdiction[0]
    else:
        legal_jurisdiction = raw_jurisdiction

    legal_name_raw = record.get("l1:legalName", record.get("legalName", ""))
    if isinstance(legal_name_raw, dict):
        legal_name = legal_name_raw.get("name", legal_name_raw.get("@value", ""))
    else:
        legal_name = legal_name_raw if legal_name_raw else ""

    legal_form_raw = record.get("l1:entityLegalFormCode", "") or record.get("legalForm", "")
    if isinstance(legal_form_raw, dict):
        legal_form = legal_form_raw.get("id", "")
    else:
        legal_form = legal_form_raw

    status_raw = record.get("l1:legalEntityStatus", record.get("status", ""))
    if isinstance(status_raw, dict):
        registration_status = status_raw.get("@id", status_raw.get("id", ""))
    else:
        registration_status = status_raw

    data = {
        "lei": lei,
        "legal_name": legal_name,
        "legal_jurisdiction": legal_jurisdiction,
        "legal_form": legal_form,
        "registration_status": registration_status,
        "legal_address": legal_address_value,
        "version": "1.0",  # Hardcoded version
        "issuing_country": "LEI",
        "issuing_authority": "LEI Lookup Demo Issuer",
    }

    cfgserv.app_logger.info(
        f"LEI lookup: Success for {lei} - name={legal_name}, "
        f"jurisdiction={legal_jurisdiction}, source=lei.info"
    )

    return data, None


def _build_presentation_data(cleaned_data):
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    presentation_data = {}
    current_session = session_manager.get_session(session_id=session["session_id"])

    for credential_requested in current_session.credentials_requested:
        credential = credentials_supported[credential_requested]
        credential_name = _resolve_display_name(credential)
        presentation_data.update({credential_name: {}})

        for claim in _resolve_claims(credential):
            claim_key = claim["path"][-1]
            if claim_key in cleaned_data:
                presentation_data[credential_name][claim_key] = cleaned_data[claim_key]

        doctype_config = credential["issuer_config"]
        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])

        presentation_data[credential_name].update(
            {
                "estimated_issuance_date": today.strftime("%Y-%m-%d"),
                "estimated_expiry_date": expiry.strftime("%Y-%m-%d"),
                "issuing_country": cleaned_data["issuing_country"],
                "issuing_authority": doctype_config["issuing_authority"],
            }
        )

        if "credential_type" in doctype_config:
            presentation_data[credential_name].update(
                {"credential_type": doctype_config["credential_type"]}
            )

    return presentation_data


@dynamic.route("/lei", methods=["GET", "POST"])
def lei_form():
    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)
    session_manager.update_country(session_id=session_id, country="LEI")

    if request.method == "GET":
        return _render_lei_form(current_session=current_session)

    if "Cancelled" in request.form.keys():
        return _render_auth_method_selection(current_session=current_session)

    lei = request.form.get("lei", "").strip().upper()

    if len(lei) != 20 or not lei.isalnum():
        return _render_lei_form(
            current_session=current_session,
            error="LEI must contain 20 letters or digits.",
            lei=lei,
        )

    cleaned_data, error = _fetch_lei_data(lei)
    if error:
        return _render_lei_form(
            current_session=current_session,
            error=error,
            lei=lei,
        )

    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)
    presentation_data = _build_presentation_data(cleaned_data=cleaned_data)

    return post_redirect_with_payload(
        target_url=f"{_get_target_frontend_url(current_session.frontend_id)}/display_authorization",
        data_payload=_build_authorization_payload(
            current_session=current_session,
            presentation_data=presentation_data,
            authorization_requires_email=True,
        ),
    )

@dynamic.route("/", methods=["GET", "POST"])
def Supported_Countries():
    """Initial PID page.
    Loads country config information and renders pid_index.html so that the user can select the PID issuer country.
    """

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)
    # session["credentials_requested"] = credentials_requested

    display_countries = {}
    for country in cfgcountries.supported_countries:
        res = all(
            ele in cfgcountries.supported_countries[country]["supported_credentials"]
            for ele in current_session.credentials_requested
        )
        if res:
            display_countries.update(
                {str(country): str(cfgcountries.supported_countries[country]["name"])}
            )

    if len(display_countries) == 1:
        country = next(iter(display_countries))

        # session["returnURL"] = cfgserv.OpenID_first_endpoint
        # session["country"] = country

        cfgserv.app_logger.info(
            ", Session ID: "
            + session["session_id"]
            + ", "
            + "Authorization selection, Type: "
            + country
        )
        return dynamic_R1(country)

    # render page where user can select pid_countries

    # session["authorization_params"] = {"token": token}

    # print("\nsession token: ", session)

    # session["jws_token"] = token  # authorization_params["token"]

    target_url = ConfFrontend.registered_frontends[current_session.frontend_id]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_countries",
        data_payload={
            "countries": display_countries,
            "authorization_details": current_session.authorization_details,
            "redirect_url": cfgserv.service_url,
            "session_id": session_id,
        },
    )


@dynamic.route("/country_selected", methods=["GET", "POST"])
def country_selected():
    # form_keys = request.form.keys()
    form_country = request.form.get("country")

    cfgserv.app_logger.info(
        ", Session ID: "
        + session["session_id"]
        + ", "
        + "Authorization selection, Type: "
        + form_country
    )

    return dynamic_R1(form_country)


def dynamic_R1(country):
    """
    Function to create url to redirect to the selected credential issuer country

    Keyword arguments:
    country -- Country selected by user
    """

    session_id = session["session_id"]
    session_manager.update_country(session_id=session_id, country=country)

    current_session = session_manager.get_session(session_id=session_id)

    credentials_requested = current_session.credentials_requested
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    if country == "FC":

        mandatory_attributes = getAttributesForm(current_session.credentials_requested)
        if "user_pseudonym" in mandatory_attributes:
            mandatory_attributes.update(
                {"user_pseudonym": {"type": "string", "filled_value": str(uuid4())}}
            )

        optional_attributes_raw = getAttributesForm2(
            current_session.credentials_requested
        )

        optional_attributes_filtered = {
            key: value
            for key, value in optional_attributes_raw.items()
            if key not in mandatory_attributes
        }

        target_url = ConfFrontend.registered_frontends[current_session.frontend_id][
            "url"
        ]

        return post_redirect_with_payload(
            target_url=f"{target_url}/display_form",
            data_payload={
                "mandatory_attributes": mandatory_attributes,
                "optional_attributes": optional_attributes_filtered,
                "redirect_url": f"{cfgserv.service_url}dynamic/form",
                "session_id": session_id,
            },
        )

        """ elif country == "sample":

        session_manager.update_user_data(
            session_id=session_id, user_data=cfgserv.sample_data.copy()
        )

        # session["returnURL"] = cfgserv.OpenID_first_endpoint

        return redirect(
            url_get(
                cfgserv.OpenID_first_endpoint,
                {
                    "token": current_session.jws_token,
                    "username": session_id,
                },
            )
        ) """

        # return redirect(cfgcountries.supported_countries[country]["pid_url_oidc"])

    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
        oauth_data = cfgcountries.supported_countries[country]["oauth_auth"]

        return redirect(
            generate_connector_authorization_url(
                oauth_data=oauth_data,
                country=country,
                credentials_requested=credentials_requested,
            )
        )

    elif cfgcountries.supported_countries[country]["connection_type"] == "openid":

        country_data = cfgcountries.supported_countries[country]["oidc_auth"]

        metadata_url = country_data["base_url"] + "/.well-known/openid-configuration"
        metadata_json = requests.get(metadata_url).json()

        authorization_endpoint = metadata_json["authorization_endpoint"]

        url = authorization_endpoint + "?redirect_uri=" + country_data["redirect_uri"]

        if country == "EE":
            country_data["state"] = country + "." + current_session.jws_token

        for url_part in country_data:
            if (
                url_part == "url"
                or url_part == "redirect_uri"
                or url_part == "base_url"
            ):
                pass
            else:
                url = url + "&" + url_part + "=" + country_data[url_part]

        return redirect(url)


@dynamic.route("/redirect", methods=["GET", "POST"])
def red():
    """Receives token from different IDPs

    GET parameters:
    + code (mandatory) - Token code to retrieve the shared attributes consented by the user.
    + scope (mandatory) - scope of the request.
    + state (mandatory) - state of the request.

    Return: Redirect answer to returnURL.
    """
    # session["route"] = "/dynamic/redirect"

    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)

    (v, l) = validate_mandatory_args(request.args, ["code"])
    if not v:  # if not all arguments are available
        raise ValueError(f"Missing mandatory IdP fields: {l}")

    auth_code = request.args.get("code")

    country_config = cfgcountries.supported_countries[current_session.country]

    metadata_url = (
        country_config["oauth_auth"]["base_url"]
        + "/.well-known/oauth-authorization-server"
    )

    metadata_json = requests.get(metadata_url).json()

    token_endpoint = metadata_json["token_endpoint"]

    token_endpoint_headers = {}
    if (
        "token_endpoint" in country_config["oauth_auth"]
        and "header" in country_config["oauth_auth"]["token_endpoint"]
    ):
        token_endpoint_headers = country_config["oauth_auth"]["token_endpoint"][
            "headers"
        ]

    if (
        "oauth_auth" in country_config
        and "client_id" in country_config["oauth_auth"]
        and "client_secret" in country_config["oauth_auth"]
    ):
        auth_string = f"{country_config['oauth_auth']['client_id']}:{country_config['oauth_auth']['client_secret']}"
        encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")

        token_endpoint_headers["Authorization"] = f"Basic {encoded_auth}"

    data = f"code={request.args.get('code')}"

    params = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": country_config["oauth_auth"]["redirect_uri"],
    }

    try:
        response = requests.post(
            token_endpoint,
            data=params,
            headers=token_endpoint_headers,
        )

        response.raise_for_status()
        token_data = response.json()

        access_token = token_data.get("access_token")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

    session["access_token"] = access_token

    data = dynamic_R2_data_collect(
        country=current_session.country,
        session_id=session_id,
        access_token=access_token,
    )

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    presentation_data = dict()

    for credential_requested in current_session.credentials_requested:

        scope = credentialsSupported[credential_requested]["scope"]

        """ if scope in cfgserv.common_name:
            credential=cfgserv.common_name[scope]

        else:
            credential = scope  """

        credential = credentialsSupported[credential_requested]["credential_metadata"][
            "display"
        ][0]["name"]

        presentation_data.update({credential: {}})

        credential_atributes_form = list()
        credential_atributes_form.append(credential_requested)
        attributesForm = getAttributesForm(credential_atributes_form).keys()

        for attribute in data.keys():
            if attribute in attributesForm:
                presentation_data[credential][attribute] = data[attribute]

        doctype_config = credentialsSupported[credential_requested]["issuer_config"]

        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])

        presentation_data[credential].update(
            {"estimated_issuance_date": today.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"estimated_expiry_date": expiry.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"issuing_country": current_session.country}
        )

        if credential_requested == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            presentation_data[credential].update(
                {
                    "issuing_authority": {
                        "id": doctype_config["issuing_authority_id"],
                        "name": doctype_config["issuing_authority"],
                    }
                }
            )
        else:
            presentation_data[credential].update(
                {"issuing_authority": doctype_config["issuing_authority"]}
            )

        if "credential_type" in doctype_config:
            presentation_data[doctype].update(
                {"credential_type": doctype_config["credential_type"]}
            )

        if "driving_privileges" in presentation_data[credential] and isinstance(
            presentation_data[credential]["driving_privileges"], str
        ):
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges": json_priv})

        fields_to_decode = [
            "portrait",
            "image",
            "signature_usual_mark",
        ]  # Add any other fields here

        for field in fields_to_decode:
            if field in presentation_data[credential]:
                presentation_data[credential].update(
                    {
                        field: base64.b64encode(
                            base64.urlsafe_b64decode(
                                presentation_data[credential][field]
                            )
                        ).decode("utf-8")
                    }
                )

        if "NumberCategories" in presentation_data[credential]:
            for i in range(int(presentation_data[credential]["NumberCategories"])):
                f = str(i + 1)
                presentation_data[credential].pop("IssueDate" + f)
                presentation_data[credential].pop("ExpiryDate" + f)
            presentation_data[credential].pop("NumberCategories")

    user_id = current_session.country + "." + session["access_token"]

    target_url = ConfFrontend.registered_frontends[current_session.frontend_id]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_authorization",
        data_payload={
            "presentation_data": presentation_data,
            "redirect_url": f"{cfgserv.service_url}dynamic/redirect_wallet",
            "session_id": session_id,
        },
    )


@dynamic.route("/dynamic_R2", methods=["GET", "POST"])
def dynamic_R2():
    """Route acessed by OpenID to get PID attributes from country FC

    Get query parameters:
    + user_id - token to obtain PID attributes

    Return:PID in sd-jwt and mdoc formats

    """

    json_request = request.json

    (v, l) = validate_mandatory_args(json_request, ["user_id", "credential_requests"])

    if not v:
        return {
            "error": "invalid_credential_request",
            "error_description": "missing fields in json",
        }

    user_id = json_request["user_id"]

    current_session = session_manager.get_session(session_id=user_id)

    country = current_session.country

    credential_request = json_request["credential_requests"]

    data = (
        current_session.user_data
    )  # dynamic_R2_data_collect(country=country, user_id=user_id)

    """ if "error" in data:
        return data """

    # log.logger_info.info(" - INFO - " + session["route"] + " - " + session['device_publickey'] + " -  entered the route")

    credential_response = credentialCreation(
        credential_request=credential_request,
        data=data,
        country=country,
        session_id=user_id,
    )

    return credential_response


def dynamic_R2_data_collect(country, session_id, access_token):
    """
    Funtion to get attributes from selected credential issuer country

    Keyword arguments:"
    user_id -- user identifier needed to get respective attributes
    country -- credential issuing country that user selected
    """

    if country == "FC":

        current_session = session_manager.get_session(session_id=session_id)

        data = current_session.user_data

        if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"}

        return data

    if country == "sample":
        """if data == "Data not found":
        return {"error": "error", "error_description": "Data not found"}"""

        current_session = session_manager.get_session(session_id=session_id)

        data = current_session.user_data

        return data

    if country == "LEI":
        current_session = session_manager.get_session(session_id=session_id)

        data = current_session.user_data

        if data == "Data not found":
            return {"error": "error", "error_description": "Data not found"}

        return data

    elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":

        """attribute_request = cfgcountries.supported_countries[country][
            "attribute_request"
        ]
        url = attribute_request["url"] + user_id
        # headers = attribute_request["header"]
        try:
            r2 = requests.get(url)
            print("\nr2", r2)
            print("\nr2", r2.text)
            json_response = r2.json()
            print("\njson_response", json_response)
            for attribute in json_response:
                if attribute["state"] == "Pending":
                    return {"error": "Pending", "response": json_response}

            data = json_response

            return data
        except:
            credential_error_resp(
                "invalid_credential_request", "openid connection failed"
            )"""

        metadata_url = (
            cfgcountries.supported_countries[country]["oauth_auth"]["base_url"]
            + "/.well-known/oauth-authorization-server"
        )

        metadata_json = requests.get(metadata_url).json()

        user_info_endpoint = metadata_json["userinfo_endpoint"]

        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(user_info_endpoint, headers=headers)

            response.raise_for_status()

            user_data = response.json()

        except requests.exceptions.RequestException as e:
            print(f"An error occurred while fetching user data: {e}")
            if response:
                print("Response Body:", response.text)

        cleaned_user_data = {}

        if country != "PT":
            if "custom_modifiers" in cfgcountries.supported_countries[country]:
                custom_modifiers = cfgcountries.supported_countries[country][
                    "custom_modifiers"
                ]

                for modifier in custom_modifiers:
                    if custom_modifiers[modifier] in user_data:
                        cleaned_user_data[modifier] = user_data[
                            custom_modifiers[modifier]
                        ]
                        user_data.pop(custom_modifiers[modifier])

        else:
            for attribute in user_data:
                if (
                    attribute["state"] == "Available"
                    and "custom_modifiers" in cfgcountries.supported_countries[country]
                    and attribute["name"]
                    in cfgcountries.supported_countries[country]["custom_modifiers"]
                ):
                    cleaned_user_data[
                        cfgcountries.supported_countries[country]["custom_modifiers"][
                            attribute["name"]
                        ]
                    ] = attribute["value"]

        cleaned_user_data["nationality"] = [country]
        cleaned_user_data["nationalities"] = [country]

        birth_places = {
            "EU": "Brussels",
            "EE": "Tallinn",
            "CZ": "Prague",
            "NL": "Amsterdam",
            "LU": "Luxembourg",
            "PT": "Lisbon",
        }

        if country in birth_places:
            cleaned_user_data["birth_place"] = birth_places[country]
            cleaned_user_data["place_of_birth"] = [{"locality": birth_places[country]}]

        session_manager.update_user_data(
            session_id=session_id, user_data=cleaned_user_data
        )

        return cleaned_user_data

    elif cfgcountries.supported_countries[country]["connection_type"] == "openid":

        attribute_request = cfgcountries.supported_countries[country][
            "attribute_request"
        ]

        metadata_url = (
            # cfgcountries.supported_countries[session["country"]]["oidc_auth"][
            #     "base_url"
            # ]
            # + "/.well-known/openid-configuration"
            cfgcountries.supported_countries[country]["oidc_auth"]["base_url"]
            + "/.well-known/openid-configuration"
        )
        metadata_json = requests.get(metadata_url).json()

        userinfo_endpoint = metadata_json["userinfo_endpoint"]

        if country == "EE":
            url = userinfo_endpoint + "?access_token=" + access_token

            headers = attribute_request["header"]
        else:
            url = userinfo_endpoint
            headers = attribute_request["header"]
            headers["Authorization"] = f"Bearer {access_token}"

        try:
            r2 = requests.get(url, headers=headers)
            json_response = json.loads(r2.text)
            data = json_response
            if (
                "custom_modifiers"
                in cfgcountries.supported_countries[country]["attribute_request"]
            ):
                custom_modifiers = cfgcountries.supported_countries[country][
                    "attribute_request"
                ]["custom_modifiers"]
                for modifier in custom_modifiers:
                    if custom_modifiers[modifier] in data:
                        data[modifier] = data[custom_modifiers[modifier]]
                        data.pop(custom_modifiers[modifier])

            data["nationality"] = [country]
            data["nationalities"] = [country]

            birth_places = {
                "EE": "Tallinn",
                "CZ": "Prague",
                "NL": "Amsterdam",
                "LU": "Luxembourg",
            }

            if country in birth_places:
                data["birth_place"] = birth_places[country]
                data["place_of_birth"] = [{"locality": birth_places[country]}]

            session_manager.update_user_data(session_id=session_id, user_data=data)

            return data
        except:
            credential_error_resp(
                "invalid_credential_request", "openid connection failed"
            )
    else:
        credential_error_resp("invalid_credential_request", "Not supported")


def credentialCreation(credential_request, data, country, session_id):
    """
    Function to create credentials requested by user

    Keyword arguments:"
    credential_request -- dictionary with credentials requested
    data -- attributes from user
    country -- credential issuing country


    """

    credentials_supported = oidc_metadata["credential_configurations_supported"]

    credential_response = {"credentials": []}

    for proof in credential_request["proofs"]:

        if "credential_identifier" in credential_request:
            doctype = credentials_supported[
                credential_request["credential_identifier"]
            ]["scope"]
            format = credentials_supported[credential_request["credential_identifier"]][
                "format"
            ]

        elif "credential_configuration_id" in credential_request:

            if (
                "vct"
                in credentials_supported[
                    credential_request["credential_configuration_id"]
                ]
            ):
                doctype = vct2doctype(
                    credentials_supported[
                        credential_request["credential_configuration_id"]
                    ]["vct"]
                )
            else:
                doctype = credentials_supported[
                    credential_request["credential_configuration_id"]
                ]["doctype"]

            format = credentials_supported[
                credential_request["credential_configuration_id"]
            ]["format"]

        else:
            return {
                "error": "invalid_credential_request",
                "error_description": "invalid request",
            }

        """ elif "vct" in credential and "format" in credential:
            doctype = vct2scope(credential["vct"])
            format = credential["format"]

        elif "format" in credential and "doctype" in credential:
            format = credential["format"]
            doctype = credential["doctype"] """

        if "jwt" in proof:
            device_publickey = proof["jwt"]

        if "attestation" in proof:
            device_publickey = proof["attestation"]

        # device_publickey = credential["device_publickey"]

        # formatting_functions = document_mappings[doctype]["formatting_functions"]

        form_data = {}
        if country == "FC":
            form_data = data

        elif country == "sample":
            form_data = data

        elif country == "LEI":
            form_data = data

        elif (
            cfgcountries.supported_countries[country]["connection_type"] == "eidasnode"
        ):
            form_data = data

        elif cfgcountries.supported_countries[country]["connection_type"] == "oauth":
            """if country == "PT":

                portuguese_fields = cfgcountries.supported_countries[country][
                    "oidc_auth"
                ]["scope"][doctype]

                for fields_pt in portuguese_fields:
                    for item in data:
                        if item["name"] == portuguese_fields[fields_pt]:
                            form_data[fields_pt] = item["value"]
                            break

                if "birth_date" in form_data:
                    form_data["birth_date"] = datetime.strptime(
                        form_data["birth_date"], "%d-%m-%Y"
                    ).strftime("%Y-%m-%d")

                if "portrait" in form_data:
                    form_data["portrait"] = base64.urlsafe_b64encode(
                        convert_png_to_jpeg(base64.b64decode(form_data["portrait"]))
                    ).decode("utf-8")

                form_data["nationality"] = ["PT"]
                form_data["nationalities"] = ["PT"]

                form_data["birth_place"] = "Lisboa"
                form_data["place_of_birth"] = [{"locality": "Lisboa"}]

            else:"""

            for attribute in data:
                form_data[attribute] = data[attribute]

        elif cfgcountries.supported_countries[country]["connection_type"] == "openid":
            if country == "PT":
                portuguese_fields = cfgcountries.supported_countries[country]["oidc"][
                    "scope"
                ][doctype]

                for fields_pt in portuguese_fields:
                    for item in data:
                        if item["name"] == portuguese_fields[fields_pt]:
                            form_data[fields_pt] = item["value"]
                            break

                form_data["birth_date"] = datetime.strptime(
                    form_data["birth_date"], "%d-%m-%Y"
                ).strftime("%Y-%m-%d")

                form_data["portrait"] = base64.urlsafe_b64encode(
                    convert_png_to_jpeg(base64.b64decode(form_data["Portrait"]))
                ).decode("utf-8")

            else:

                for attribute in data:
                    form_data[attribute] = data[attribute]

        else:
            return {
                "error": "invalid_credential_request",
                "error_description": "invalid request",
            }

        form_data.update(
            {
                "issuing_country": country,
            }
        )

        pdata = dynamic_formatter(
            format, doctype, form_data, device_publickey, session_id
        )

        credential_response["credentials"].append({"credential": pdata})

        """ formatting_function_data = formatting_functions.get(format)

        if formatting_function_data:
            formatting_function = formatting_function_data["formatting_function"]
            f = globals().get(formatting_function)

            pdata = f(form_data, device_publickey)
            # credential_response.update({f"{doctype}_{format}": pdata})

            credential_response["credential_responses"].append(
                {"credential": pdata}
            ) """

    return credential_response


@dynamic.route("/auth_method", methods=["GET", "POST"])
def auth():

    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        raise ValueError(f"User canceled authentication. Session ID: {session_id}")

    choice = request.form.get("optionsRadios")

    if choice == "link1":
        return redirect(cfgserv.service_url + "oid4vp")
    elif choice == "link2":
        return redirect(cfgserv.service_url + "dynamic/")
    elif choice == "link3":
        return redirect(cfgserv.service_url + "dynamic/lei")


def form_formatter(form_data: dict) -> dict:
    cleaned_data = {}

    # Handle date formatting first, as it's a simple key-value replacement
    if "effective_from_date" in form_data:
        date_part = form_data["effective_from_date"].split("T")[0]
        dt = datetime.strptime(date_part, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        rfc3339_string = dt.isoformat().replace("+00:00", "Z")
        form_data.update({"effective_from_date": rfc3339_string})

    # Regex to parse keys like 'capacities[0][codes][1][code]' into a list of parts
    key_pattern = re.compile(r"([^\[\]]+)")

    # Sort keys to ensure parent structures (e.g., capacities[0]) are processed before children (e.g., capacities[0][codes][0])
    for key in sorted(form_data.keys()):
        value = form_data[key]

        # Skip empty values and form control buttons
        if not value or key in ["proceed", "Cancelled", "NumberCategories"]:
            continue
        if "option" in key and "on" in value:
            continue

        parts = key_pattern.findall(key)

        current_level = cleaned_data
        for i, part in enumerate(parts[:-1]):
            is_numeric_index = part.isdigit()

            if is_numeric_index:
                idx = int(part)
                # Ensure the list is long enough to accommodate the index
                while len(current_level) <= idx:
                    current_level.append({})
                current_level = current_level[idx]
            else:  # It's a dictionary key (e.g., 'capacities', 'codes')
                is_next_part_index = (i + 1 < len(parts)) and parts[i + 1].isdigit()

                if is_next_part_index:
                    # If the next part is an index, this key must point to a list
                    current_level = current_level.setdefault(part, [])
                else:
                    # Otherwise, it points to a dictionary
                    current_level = current_level.setdefault(part, {})

        # Set the final value at the correct location
        final_key = parts[-1]
        if final_key.isdigit() and isinstance(current_level, list):
            idx = int(final_key)
            while len(current_level) <= idx:
                current_level.append(None)
            current_level[idx] = value
        else:
            current_level[final_key] = value

    # Fixing places of work data send after restructuring project for nested issues
    if "places_of_work" in cleaned_data and isinstance(
        cleaned_data.get("places_of_work"), list
    ):
        aggregated_data = {}
        # Loop through the list generated by the parser (e.g., [{'no_fixed_place': [...]}, {'no_fixed_place': [...]}])
        for item in cleaned_data["places_of_work"]:
            if isinstance(item, dict):
                # An item is like {'no_fixed_place': [{'country_code': 't1'}]}
                for key, value_list in item.items():
                    # Initialize the key in our aggregator if it's not there
                    if key not in aggregated_data:
                        aggregated_data[key] = []
                    # Add the items from the current list to the aggregator's list
                    if isinstance(value_list, list):
                        aggregated_data[key].extend(value_list)

        # If we successfully aggregated data, replace the original list
        if aggregated_data:
            cleaned_data["places_of_work"] = [aggregated_data]

    # Final transformation for nationalities
    for key in ["nationality", "nationalities"]:
        if key in cleaned_data and isinstance(cleaned_data[key], list):
            # Check if the list contains dictionaries (it should from the form)
            if cleaned_data[key] and isinstance(cleaned_data[key][0], dict):
                # Use a list comprehension to extract the 'country_code' from each dictionary.
                cleaned_data[key] = [
                    item.get("country_code")
                    for item in cleaned_data[key]
                    if "country_code" in item
                ]

    # Perform any final data transformations if necessary
    if "portrait" in cleaned_data:
        if cleaned_data["portrait"] == "Port1":
            cleaned_data["portrait"] = cfgserv.portrait1
        elif cleaned_data["portrait"] == "Port2":
            cleaned_data["portrait"] = cfgserv.portrait2
        # Note: File upload logic for Port3 remains in the main route function

    if "image" in cleaned_data:
        if cleaned_data["image"] == "Port1":
            cleaned_data["image"] = cfgserv.portrait1
        elif cleaned_data["image"] == "Port2":
            cleaned_data["image"] = cfgserv.portrait2

    if "signature_usual_mark" in cleaned_data:
        if cleaned_data["signature_usual_mark"] == "Sig1":
            cleaned_data["signature_usual_mark"] = (
                cfgserv.signature_usual_mark_issuing_officer
            )

    if "signature_usual_mark_issuing_officer" in cleaned_data:
        if cleaned_data["signature_usual_mark_issuing_officer"] == "Sig1":
            cleaned_data["signature_usual_mark_issuing_officer"] = (
                cfgserv.signature_usual_mark_issuing_officer
            )

    # Add issuer-filled data
    cleaned_data.update(
        {"issuing_country": session_manager.get_session(session["session_id"]).country}
    )

    final_data = {}
    for item, value in cleaned_data.items():
        if item in [
            "portrait",
            "image",
            "picture",
            "signature_usual_mark",
            "signature_usual_mark_issuing_officer",
        ]:
            if value == "Port1":
                final_data[item] = cfgserv.portrait1
            elif value == "Port2":
                final_data[item] = cfgserv.portrait2
            else:
                # If it's not Port1 or Port2, it's the base64url string from the route handler.
                final_data[item] = value
        else:
            final_data[item] = value

    # Add issuer-filled data

    final_data.update(
        {"issuing_country": session_manager.get_session(session["session_id"]).country}
    )

    return final_data


def presentation_formatter(cleaned_data: dict) -> dict:

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    presentation_data = dict()

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)
    credentials_requested = current_session.credentials_requested

    for credential_requested in credentials_requested:

        scope = credentialsSupported[credential_requested]["scope"]
        """ if scope in cfgserv.common_name:
            credential=cfgserv.common_name[scope]

        else:
            credential = scope """

        credential = credentialsSupported[credential_requested]["credential_metadata"][
            "display"
        ][0]["name"]

        presentation_data.update({credential: {}})

        credential_atributes_form = list()
        credential_atributes_form.append(credential_requested)
        attributesForm = getAttributesForm(credential_atributes_form).keys()
        attributesForm2 = getAttributesForm2(credential_atributes_form).keys()

        for attribute in cleaned_data.keys():

            if attribute in attributesForm:
                presentation_data[credential][attribute] = cleaned_data[attribute]

            if attribute in attributesForm2:
                presentation_data[credential][attribute] = cleaned_data[attribute]

        if "issuer_config" in credentialsSupported[credential_requested]:
            doctype_config = credentialsSupported[credential_requested]["issuer_config"]

        today = date.today()
        expiry = today + timedelta(days=doctype_config["validity"])

        presentation_data[credential].update(
            {"estimated_issuance_date": today.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"estimated_expiry_date": expiry.strftime("%Y-%m-%d")}
        )
        presentation_data[credential].update(
            {"issuing_country": current_session.country}
        )

        if credential_requested == "eu.europa.ec.eudi.seafarer_mdoc":
            presentation_data[credential].update(
                {
                    "issuing_authority_logo": base64.b64encode(
                        base64.urlsafe_b64decode(cfgserv.issuing_authority_logo)
                    ).decode("utf-8")
                }
            )

        if credential_requested == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            presentation_data[credential].update(
                {
                    "issuing_authority": {
                        "id": doctype_config["issuing_authority_id"],
                        "name": doctype_config["issuing_authority"],
                    }
                }
            )
        else:
            presentation_data[credential].update(
                {"issuing_authority": doctype_config["issuing_authority"]}
            )

        if "credential_type" in doctype_config:
            presentation_data[credential].update(
                {"credential_type": doctype_config["credential_type"]}
            )

        if (
            "birth_date" in presentation_data[credential]
            and "age_over_18" in presentation_data[credential]
        ):
            presentation_data[credential].update(
                {
                    "age_over_18": (
                        True
                        if calculate_age(presentation_data[credential]["birth_date"])
                        >= 18
                        else False
                    )
                }
            )

        if scope == "org.iso.18013.5.1.mDL":
            if "birth_date" in presentation_data[credential]:
                presentation_data[credential].update(
                    {
                        "age_over_18": (
                            True
                            if calculate_age(
                                presentation_data[credential]["birth_date"]
                            )
                            >= 18
                            else False
                        )
                    }
                )

        if "driving_privileges" in presentation_data[credential] and isinstance(
            presentation_data[credential]["driving_privileges"], str
        ):
            json_priv = json.loads(presentation_data[credential]["driving_privileges"])
            presentation_data[credential].update({"driving_privileges": json_priv})

        fields_to_decode = [
            "portrait",
            "image",
            "signature_usual_mark",
            "signature_usual_mark_issuing_officer",
            "picture",
        ]

        for field in fields_to_decode:
            if field in presentation_data[credential]:
                presentation_data[credential].update(
                    {
                        field: base64.b64encode(
                            base64.urlsafe_b64decode(
                                presentation_data[credential][field]
                            )
                        ).decode("utf-8")
                    }
                )

        if "NumberCategories" in presentation_data[credential]:
            for i in range(int(presentation_data[credential]["NumberCategories"])):
                f = str(i + 1)
                presentation_data[credential].pop("IssueDate" + f)
                presentation_data[credential].pop("ExpiryDate" + f)
            presentation_data[credential].pop("NumberCategories")

    return presentation_data


@dynamic.route("/form", methods=["GET", "POST"])
def Dynamic_form():
    """Form PID page.
    Form page where the user can enter its PID data.
    """
    # session["route"] = "/dynamic/form"
    # session["country"] = "FC"

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)

    # if GET
    if request.method == "GET":
        if (
            session.get("country") is None or session.get("returnURL") is None
        ):  # someone is trying to connect directly to this endpoint
            return (
                "Error 101: " + cfgserv.error_list["101"] + "\n",
                status.HTTP_400_BAD_REQUEST,
            )

    # if submitted form is valid
    """  v = validate_params_getpid_or_mdl(
        request.form,
        ["version", "country", "certificate", "returnURL", "device_publickey"],
    )
    if not isinstance(v, bool):  # getpid params were not correctly validated
        return v """

    user_id = session_id

    form_data = request.form.to_dict()

    form_data.pop("proceed")

    cleaned_data = form_formatter(form_data)

    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)

    presentation_data = presentation_formatter(cleaned_data=cleaned_data)

    target_url = ConfFrontend.registered_frontends[current_session.frontend_id]["url"]

    return post_redirect_with_payload(
        target_url=f"{target_url}/display_authorization",
        data_payload={
            "presentation_data": presentation_data,
            "redirect_url": f"{cfgserv.service_url}dynamic/redirect_wallet",
            "session_id": session_id,
        },
    )


@dynamic.route("/redirect_wallet", methods=["GET", "POST"])
def redirect_wallet():

    form_data = request.form.to_dict()
    user_id = form_data["user_id"]

    session_id = session["session_id"]

    current_session = session_manager.get_session(session_id=session_id)

    if current_session.country == "LEI":
        employee_email = request.form.get("employee_email", "").strip().lower()
        otp_code = request.form.get("otp_code", "").strip()
        company_name = ""
        if current_session.user_data:
            company_name = current_session.user_data.get("legal_name", "")

        email_error = _validate_employee_email(
            employee_email=employee_email,
            company_name=company_name,
        )
        if email_error:
            return _render_lei_authorization(
                current_session=current_session,
                error=email_error,
                employee_email=employee_email,
                otp_sent=bool(current_session.tx_code),
                otp_code=otp_code,
            )

        updated_user_data = dict(current_session.user_data or {})
        updated_user_data["employee_email"] = employee_email
        session_manager.update_user_data(
            session_id=session_id,
            user_data=updated_user_data,
        )

        if "send" in request.form or "resend" in request.form:
            generated_otp = random.randint(100000, 999999)
            session_manager.update_tx_code(session_id=session_id, tx_code=generated_otp)

            sent, send_error = _send_otp_email(
                recipient_email=employee_email,
                otp_code=generated_otp,
                company_name=company_name,
            )
            return _render_lei_authorization(
                current_session=session_manager.get_session(session_id=session_id),
                error=send_error,
                employee_email=employee_email,
                otp_sent=sent,
                info_message=(
                    "Verification code sent to your email."
                    if sent
                    else ""
                ),
            )

        if not current_session.tx_code:
            return _render_lei_authorization(
                current_session=current_session,
                error="Send the verification code first.",
                employee_email=employee_email,
                otp_code=otp_code,
            )

        if not otp_code:
            return _render_lei_authorization(
                current_session=current_session,
                error="Enter the verification code to continue.",
                employee_email=employee_email,
                otp_sent=True,
            )

        if otp_code != str(current_session.tx_code):
            return _render_lei_authorization(
                current_session=current_session,
                error="Verification code is incorrect.",
                employee_email=employee_email,
                otp_sent=True,
                otp_code=otp_code,
            )

    return redirect(
        url_get(
            cfgserv.OpenID_first_endpoint,
            {
                "token": current_session.jws_token,
                "username": session_id,
            },
        )
    )


""" @dynamic.route("/redirect_wallet", methods=["GET", "POST"])
def redirect_wallet():

    form_data = request.form.to_dict()

    user_id = form_data["user_id"]

    print("\nuser_id: ", user_id)
    print("\ntoken: ", session["authorization_params"]["token"])

    return redirect(
        url_get(
            cfgserv.OpenID_first_endpoint,
            {
                "jws_token": session["authorization_params"]["token"],
                "username": user_id,
            },
        )
    ) """


def generate_connector_authorization_url(
    oauth_data: dict, country: str, credentials_requested: list
):
    metadata_url = (
        f"{oauth_data.get('base_url')}/.well-known/oauth-authorization-server"
    )

    metadata_json = requests.get(metadata_url).json()

    authorization_endpoint = metadata_json["authorization_endpoint"]

    state = str(uuid4())
    session["oauth_state"] = state

    params = {
        "client_id": oauth_data["client_id"],
        "redirect_uri": oauth_data["redirect_uri"],
        "response_type": "code",
        "scope": credentials_requested[0],
        "state": state,
        "entity": country,
        # "credentials_requested": credentials_requested[0],
        # "metadata_url": f"{cfgserv.service_url}.well-known/openid-credential-issuer2",
    }

    full_url = f"{authorization_endpoint}?{urlencode(params)}"

    return full_url
