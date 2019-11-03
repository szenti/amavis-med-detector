#!/usr/bin/env python

import os
import sys
import logging
import subprocess
import re
from collections import OrderedDict
import json


MIME_TYPES_TO_CHECK = [
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-office']

MACRO_FLAGS = {
        '^\|\s*AutoExec': 'executes automatically',
        '^\|\s*Suspicious\s*\|\s*Shell': 'executes file(s)',
        '^\|\s*Suspicious\s*\|\s*User-Agent': 'download file(s)',
        '^\|\s*Suspicious': 'have suspicious strings',
}

class Document:
    __logger = None
    __macro_flags = {}
    __hide_details = False

    def __init__(self, filename, hide_details=False):
        self._file_path = filename
        self._file_name, self._extension = os.path.splitext(os.path.split(filename)[1])
        self._file_name += self._extension
        self.__hide_details = hide_details
        self.initialize()

    def initialize(self):
        self._load_config()
        return self

    def _load_config(self):
        script_directory = os.path.dirname(__file__)
        config_file_path = os.path.join(script_directory, 'document_config.json')

        with open(config_file_path, 'r') as file:
            self.__config = json.load(file)

    @property
    def _logger(self):
        if Document.__logger is None:
            Document.__logger = logging.getLogger('document')
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            Document.__logger.addHandler(console_handler)
            Document.__logger.setLevel(logging.WARNING)

        return Document.__logger

    @property
    def _macro_flags(self):
        if not Document.__macro_flags:
            Document.__macro_flags = [{ 'regexp': re.compile(exp, re.MULTILINE), 'test': exp, 'flag': flag } for exp, flag in MACRO_FLAGS.iteritems()]

        return Document.__macro_flags

    def check(self):
        try:
            self._read_config()
            self._check_file_exists()
            self._check_contains_malicious_macro()
            self._log_clean()
        except SkipChecks:
            return
        except Exception as ex:
            self._logger.error(ex)
            return

    def _read_config(self):
        pass


    def _check_file_exists(self):
        if not os.path.exists(self._file_path):
            self._logger.error('File {0} does not exist'.format(self._file_path))
            raise SkipChecks()

        if not os.path.isfile(self._file_path):
            raise SkipChecks()

    def _get_type(self):
        command = [self.__config['paths']['file'], '--brief', '--mime', self._file_path]
        output = self._get_command_output(command)
        return output.lower()

    def _log_clean(self):
        self._logger.info('{0} OK'.format(self._file_name))

    def _check_contains_malicious_macro(self):
        document_type = self._get_type()
        if document_type.startswith('application/xml'):
            # Kann eine MS Office-Datei ohne ZIP-Container sein.
            # Dreckiger Hack: mit GREP scannen.
            if self._get_command_output(['grep', '-m1', '<?mso-application', self._file_path]) != '':
                return self._check_macro_flags()

        for mime_type in MIME_TYPES_TO_CHECK:
            if mime_type in document_type:
                return self._check_macro_flags()

    def _check_macro_flags(self):
        params = [self.__config['paths']['olevba'], '-a', self._file_path]
        output = self._get_command_output(params)
        flags = self.__compute_macro_flags(output)
        if len(flags) > 0:
            self._log_infected(flags)

    @staticmethod
    def _get_command_output(command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process.stdout.read()

    def __compute_macro_flags(self, output):
        result = []
        for test in self._macro_flags:
            if test['regexp'].findall(output):
                result.append(test['flag'])
        return result

    def _log_infected(self, flags):
        message = self._get_log_message(flags)
        self._logger.error(message)

    def _get_log_message(self, flags):
        if self.__hide_details:
            return 'VIRUS Dangerous macro'

        return 'VIRUS Contains macro(s) that ' + ', '.join(flags)


class SkipChecks(RuntimeError):
    pass
