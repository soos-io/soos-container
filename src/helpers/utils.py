from sys import exit
from base64 import b64encode
from typing import NoReturn
from requests import Response
import helpers.constants as Constants
from model.log_level import LogLevel, loggerFunc


def log(message: str, log_level: LogLevel = LogLevel.INFO) -> None:
    logFunc = loggerFunc.get(log_level)
    logFunc(str(message))

def log_error(api_response: Response) -> None:
    log(f"Status Code: {api_response.status_code}", log_level=LogLevel.ERROR)
    if api_response.text is not None:
        log(f"Response Text: {api_response.text}", log_level=LogLevel.ERROR)

def exit_app(e) -> NoReturn:
    log(str(e), LogLevel.ERROR)
    exit(1)

def valid_required(key, value):
    if value is None or len(value) == 0:
        exit_app(key + " is required")
    return value

def print_line_separator() -> None:
    print(
        "----------------------------------------------------------------------------------------------------------"
    )

def convert_string_to_b64(content: str) -> str:
    message_bytes = content.encode(Constants.UTF_8)
    base64_bytes = b64encode(message_bytes)
    base64_message = base64_bytes.decode(Constants.UTF_8)
    return base64_message

def read_file(file_path):
    with open(file=file_path, mode=Constants.FILE_READ_MODE, encoding=Constants.UTF_8) as file:
        return file.read()