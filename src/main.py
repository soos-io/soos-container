from argparse import ArgumentParser, Namespace
import logging
import os
import platform
import json
from datetime import datetime
from requests import Response, put, post, patch
from typing import Optional, Dict, Any
import helpers.constants as Constants
from helpers.utils import convert_string_to_b64, exit_app, log_error, print_line_separator, read_file, valid_required, log
from model.log_level import LogLevel

ANALYSIS_START_TIME = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
OPERATING_ENVIRONMENT = f'{platform.system()} {platform.release()} {platform.architecture()[0]}'

with open(os.path.join(os.path.dirname(__file__), "VERSION.txt"), encoding='UTF-8') as version_file:
    SCRIPT_VERSION = version_file.read().strip()

class CsaStartAnalysisResponse:
    def __init__(self, csa_analysis_api_response):
        self.analysis_id = csa_analysis_api_response[
            "analysisId"] if "analysisId" in csa_analysis_api_response else None
        self.branch_hash = csa_analysis_api_response[
            "branchHash"] if "branchHash" in csa_analysis_api_response else None
        self.scan_type = csa_analysis_api_response["scanType"] if "scanType" in csa_analysis_api_response else None
        self.scan_url = csa_analysis_api_response["scanUrl"] if "scanUrl" in csa_analysis_api_response else None
        self.scan_status_url = csa_analysis_api_response[
            "scanStatusUrl"] if "scanStatusUrl" in csa_analysis_api_response else None
        self.errors = csa_analysis_api_response["errors"] if "errors" in csa_analysis_api_response else None
        self.project_id = csa_analysis_api_response["projectId"] if "projectId" in csa_analysis_api_response else None
        if self.project_id is None:
            self.project_id = csa_analysis_api_response[
                "projectHash"] if "projectHash" in csa_analysis_api_response else None

class SOOSCsaAnalysis:
    
    def __init__(self):
        # Common SOOS variables
        self.client_id: Optional[str] = None
        self.api_key: Optional[str] = None
        self.project_name: Optional[str] = None
        self.base_uri: Optional[str] = None
        self.on_failure: Optional[str] = None
        self.log_level: Optional[str] = None

        # Special Context - loads from script arguments only
        self.commit_hash: Optional[str] = None
        self.branch_name: Optional[str] = None
        self.branch_uri: Optional[str] = None
        self.build_version: Optional[str] = None
        self.build_uri: Optional[str] = None
        self.operating_environment: Optional[str] = None

        # Hardcoded values
        self.integration_name: str = Constants.DEFAULT_INTEGRATION_NAME
        self.integration_type: str = Constants.DEFAULT_INTEGRATION_TYPE
        self.csa_analysis_tool: str = Constants.DEFAULT_CSA_TOOL
        self.csa_analysis_tool_version: str = Constants.DEFAULT_CSA_TOOL_VERSION

        # Trivy specific params
        self.scan_type: str = Constants.DEFAULT_SCAN_TYPE
        self.format: str = Constants.DEFAULT_SCAN_FORMAT
        self.output: str = Constants.DEFAULT_SCAN_OUTPUT
        self.severity: Optional[str] = Constants.DEFAULT_SCAN_SEVERITY
        self.target_to_scan: Optional[str] = None
        self.vulnerability_types: Optional[str] = Constants.DEFAULT_VULNERABILITY_TYPES
        self.debug: bool = False

    def parse_configuration(self, configuration: Dict, target_to_scan: str):
        self.log_level = configuration.get("logLevel", LogLevel.INFO)
        logging.getLogger("SOOS Csa").setLevel(self.log_level)
        log(json.dumps(configuration, indent=2), log_level=LogLevel.DEBUG)
        # Common SOOS variables
        self.client_id = configuration.get("clientId")
        if self.client_id is None:
            self.client_id = os.environ.get(Constants.SOOS_CLIENT_ID)
            valid_required("clientId", self.client_id)

        self.api_key = configuration.get("apiKey")
        if self.api_key is None:
            self.api_key = os.environ.get(Constants.SOOS_API_KEY)
            valid_required("apiKey", self.api_key)
        self.project_name = valid_required("projectName", configuration.get("projectName"))
        self.base_uri = configuration.get("apiURL", Constants.DEFAULT_BASE_URL)
        self.on_failure = configuration.get("onFailure")

        # Special Context - loads from script arguments only
        self.commit_hash = configuration.get("commitHash")
        self.branch_name = configuration.get("branchName")
        self.branch_uri = configuration.get("branchURI")
        self.build_version = configuration.get("buildVersion")
        self.build_uri = configuration.get("buildURI")
        self.operating_environment = configuration.get("operatingEnvironment", OPERATING_ENVIRONMENT)

        # Trivy specific params
        self.severity = configuration.get("severity", Constants.DEFAULT_SCAN_SEVERITY)
        self.target_to_scan = valid_required("Target to scan", target_to_scan)
        self.vulnerability_types = configuration.get("vulnerabilityTypes", Constants.DEFAULT_VULNERABILITY_TYPES)
        self.debug = configuration.get("debug", False)
    
    def parse_args(self) -> None:
        parser = ArgumentParser(description="SOOS Csa")

        # DOCUMENTATION

        parser.add_argument('-hf', "--helpFormatted", dest="help_formatted",
                            help="Print the --help command in markdown table format",
                            action="store_false",
                            default=False,
                            required=False)

        # SCRIPT PARAMETERS

        parser.add_argument(
            "targetToScan",
            help="The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
        )
        parser.add_argument("--clientId", help="SOOS Client ID - get yours from https://app.soos.io/integrate/sca", required=False)
        parser.add_argument("--apiKey", help="SOOS API Key - get yours from https://app.soos.io/integrate/sca", required=False)
        parser.add_argument("--projectName", help="Project Name - this is what will be displayed in the SOOS app.", required=False)
        parser.add_argument(
            "--apiURL",
            help="SOOS API URL - Intended for internal use only, do not modify.",
            default="https://api.soos.io/api/",
            required=False,
        )
        parser.add_argument(
            "--logLevel",
            help="Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
            default="INFO",
            required=False,
        )
        parser.add_argument(
            "--severity",
            help="Comma separated list of vulnerability severities to include in the report. Default is 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL' (all possible values).",
            default=Constants.DEFAULT_SCAN_SEVERITY,
            required=False,
        )
        parser.add_argument(
            "--vulnerabilityTypes",
            help="Comma separated list of vulnerability types to include in the report. Possible values: os, library.",
            default=Constants.DEFAULT_VULNERABILITY_TYPES,
            required=False,
        )
        parser.add_argument(
            "--debug",
            help="Enable debug logging on trivy.",
            action="store_true",
            default=False,
            required=False,
        )
        parser.add_argument(
            "--integrationName",
            help="Integration Name - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--integrationType",
            help="Integration Type - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--scriptVersion",
            help="Script Version - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--appVersion",
            help="App Version - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--onFailure",
            help="Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
            type=str,
            default="continue_on_failure",
            required=False,
        )
        parser.add_argument(
            "--commitHash",
            help="The commit hash value from the SCM System.",
            type=str,
            default=None,
            required=False,
        )
        parser.add_argument(
            "--branchName",
            help="The name of the branch from the SCM System.",
            type=str,
            default=None,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--branchURI",
            help="The URI to the branch from the SCM System.",
            default=None,
            required=False,
        )
        parser.add_argument(
            "--buildVersion",
            help="Version of application build artifacts.",
            type=str,
            default=None,
            required=False,
        )
        parser.add_argument(
            "--buildURI",
            help="URI to CI build info.",
            type=str,
            default=None,
            required=False,
        )
        parser.add_argument(
            "--operatingEnvironment",
            help="Set Operating environment for information purposes only.",
            type=str,
            default=None,
            nargs="*",
            required=False,
        )
        log("Parsing arguments", log_level=LogLevel.INFO)")
        args: Namespace = parser.parse_args()
        self.parse_configuration(vars(args), args.targetToScan)

    def get_command(self):
        base_command = Constants.DEFAULT_COMMAND_TEMPLATE.format(severity=self.severity, vulnerability_types=self.vulnerability_types, format=self.format, output=self.output, scan_type=self.scan_type, target_to_scan=self.target_to_scan)
        full_command = self.add_trivy_extra_args(base_command)
        return full_command

    def add_trivy_extra_args(self, command: str) -> str:
        if self.debug:
            command += " --debug"
        return command

    def __generate_start_analysis_url__(self) -> str:
        url = Constants.URI_START_CSA_ANALYSIS_TEMPLATE.format(soos_base_uri=self.base_uri,
                                                                soos_client_id=self.client_id)

        return url

    def __generate_upload_results_url__(self, project_id: str, branch_hash: str, analysis_id: str) -> str:
        url = Constants.URI_UPLOAD_CSA_RESULTS_TEMPLATE.format(soos_base_uri=self.base_uri,
                                                                   soos_client_id=self.client_id,
                                                                   soos_project_id=project_id,
                                                                   soos_branch_hash=branch_hash,
                                                                   soos_analysis_id=analysis_id)
        return url
    
    def start_soos_analysis_request(self) -> CsaStartAnalysisResponse:
        message: str = "An error has occurred Starting the Analysis"
        try:
            log("Making request to SOOS")
            api_url: str = self.__generate_start_analysis_url__()
            log(f"SOOS URL Endpoint: {api_url}")

            param_values: dict = dict(
                projectName=self.project_name,
                name=datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                integrationType=self.integration_type,
                scriptVersion=SCRIPT_VERSION,
                scanMode=self.scan_type,
                toolName=self.csa_analysis_tool,
                toolVersion=self.csa_analysis_tool_version,
                commitHash=self.commit_hash,
                branch=self.branch_name,
                branchUri=self.branch_uri,
                buildVersion=self.build_version,
                buildUri=self.build_uri,
                operationEnvironment=self.operating_environment,
                integrationName=self.integration_name,
            )

            # Clean up None values
            request_body = {k: v for k, v in param_values.items() if v is not None}

            error_response: Optional[Any] = None

            data = json.dumps(request_body)

            api_response: Response = post(
                url=api_url,
                data=data,
                headers={"x-soos-apikey": self.api_key, "Content-Type": Constants.JSON_HEADER_CONTENT_TYPE}
            )

            if api_response.ok:
                return CsaStartAnalysisResponse(api_response.json())
            else:
                log_error(api_response)
                error_response = api_response
                log(
                    "An error has occurred performing the request."
                )

            if error_response is not None:
                error_response = error_response.json()
                message = error_response["message"]

        except Exception as error:
            log(f"Error: {error}")
            message = message if message is not None else "An error has occurred Starting the Analysis"

        exit_app(message)
    
    def publish_results_to_soos(self, project_id: str, branch_hash: str, analysis_id: str, report_url: str) -> None:
        try:
            self.upload_csa_results_request(project_id=project_id, branch_hash=branch_hash,
                                                      analysis_id=analysis_id)

            print_line_separator()
            log("Report processed successfully")
            log(f"Project Id: {project_id}")
            log(f"Branch Hash: {branch_hash}")
            log(f"Analysis Id: {analysis_id}")
            print_line_separator()
            log("SOOS Csa Analysis successful")
            log(f"Project URL: {report_url}")
            print_line_separator()

        except Exception as error:
            self.soos_scan_status_request(project_id=project_id,
                                                   branch_hash=branch_hash,
                                                   analysis_id=analysis_id,
                                                   status="Error",
                                                   status_message="An Unexpected error has occurred uploading Trivy Report Results"
                                                   )
            exit_app(error)

    def upload_csa_results_request(
            self, project_id: str, branch_hash: str, analysis_id: str
    ) -> bool:
        error_response = None
        error_message: Optional[str] = None
        try:
            log("Starting report results processing")
            csa_report = self.open_results_file()
            log("Making request to SOOS")
            api_url: str = self.__generate_upload_results_url__(project_id, branch_hash, analysis_id)
            log("SOOS URL Upload Results Endpoint: " + api_url)
            results_json = json.loads(csa_report)
            log(json.dumps(results_json, indent=2), log_level=LogLevel.DEBUG)

            trivy_report_encoded = convert_string_to_b64(json.dumps(results_json))
            files = {"base64Manifest": trivy_report_encoded}

            api_response: Response = put(
                url=api_url,
                data=dict(resultVersion=results_json["SchemaVersion"]),
                files=files,
                headers={
                    "x-soos-apikey": self.api_key,
                    "Content_type": Constants.MULTIPART_HEADER_CONTENT_TYPE,
                },
            )

            if api_response.ok:
                log("SOOS Upload Success")
                return True
            else:
                error_response = api_response
                log_error(error_response)
                log("An error has occurred performing the request")

            if  error_response is not None:
                error_response = error_response.json()
                error_message = error_response["message"]

        except Exception as error:
            log(f"Error: {error}")

        self.soos_scan_status_request(project_id=project_id,
                                               branch_hash=branch_hash,
                                               analysis_id=analysis_id,
                                               status="Error",
                                               status_message=error_message
                                               )
        exit_app(error_message)
    
    def soos_scan_status_request(self, project_id: str, branch_hash: str,
                                          analysis_id: str, status: str,
                                          status_message: Optional[str]) -> bool:
        message: str = "An error has occurred Starting the Analysis"
        try:
            log("Making request to SOOS")
            api_url: str = self.__generate_upload_results_url__(project_id, branch_hash, analysis_id)
            log(f"SOOS URL Endpoint: {api_url}")

            param_values: dict = dict(
                status=status,
                message=status_message
            )

            # Clean up None values
            request_body = {k: v for k, v in param_values.items() if v is not None}

            error_response: Optional[Any] = None

            data = json.dumps(request_body)

            api_response: Response = patch(
                url=api_url,
                data=data,
                headers={"x-soos-apikey": self.api_key, "Content-Type": Constants.JSON_HEADER_CONTENT_TYPE}
            )

            if api_response.ok:
                return True
            else:
                log_error(api_response)
                error_response = api_response
                log(
                    "An error has occurred performing the request"
                )

            if  error_response is not None:
                error_response = error_response.json()
                message = error_response["message"]

        except Exception as error:
            log(f"Error: {error}")
            message = message if message is not None else "An error has occurred setting the scan status"
            self.soos_scan_status_request(project_id=project_id,
                                                   branch_hash=branch_hash,
                                                   analysis_id=analysis_id,
                                                   status="Error",
                                                   status_message=message
                                                   )

        exit_app(message)
    
    def open_results_file(self):
        return read_file(file_path=Constants.REPORT_SCAN_RESULT_FILENAME)
    
    
    def run_analysis(self) -> None:
        try:
            log("Starting SOOS Csa Analysis")
            print_line_separator()

            self.parse_args()

            log("Configuration read")
            print_line_separator()

            log(f"Project Name: {self.project_name}")
            log(f"API URL: {self.base_uri}")
            log(f"Target to Scan: {self.target_to_scan}")
            print_line_separator()

            log(f"Starting execution of Csa scan")
            soos_csa_start_response = self.start_soos_analysis_request()

            command = self.get_command()
            log(f"Executing command: {command}")
            try:
                os.system(command)
            except Exception as error:
                log(f"There was an error during trivy execution: {error}")
                exit_app(error)
            
            print_line_separator()

            self.publish_results_to_soos(
                project_id=soos_csa_start_response.project_id,
                branch_hash=soos_csa_start_response.branch_hash,
                analysis_id=soos_csa_start_response.analysis_id,
                report_url=soos_csa_start_response.scan_url,
            )
        except Exception as error:
            log(f"Error: {error}")
            exit_app(error)


if __name__ == "__main__":
    csaAnalysis = SOOSCsaAnalysis()
    csaAnalysis.run_analysis()
    