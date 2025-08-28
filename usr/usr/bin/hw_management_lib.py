# Copyright (c) 2019-2024 NVIDIA CORPORATION & AFFILIATES.
# Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#############################################################################

import os
import sys
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
import syslog
from threading import Timer
import time

# ----------------------------------------------------------------------


def str2bool(val):
    """
    @summary:
        Convert input val value (y/n, true/false, 1/0, y/n) to bool
    @param val: input value.
    @return: True or False
    """
    if isinstance(val, bool):
        return val
    elif isinstance(val, int):
        return bool(val)
    elif val.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif val.lower() in ("no", "false", "f", "n", "0"):
        return False
    return None


# ----------------------------------------------------------------------
def current_milli_time():
    """
    @summary:
        get current time in milliseconds
    @return: int value time in milliseconds
    """
    return round(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)

class HW_Mgmt_Logger(object):
    """
    Logger class provide functionality to log messages.
    It can log to several places in parallel

    Level       When to Use

    DEBUG   For detailed diagnostic info. Only useful for developers
                during debugging.

    INFO    For normal runtime events. High-level messages showing the
                system is working as expected.

    NOTICE  For important but non-critical events. More significant than `INFO`,
                but not a problem.

    WARNING For unexpected events that didn't cause a failure, but might.

    ERROR   For serious issues that caused part of the system to fail.
    """
    CRITICAL = logging.CRITICAL
    FATAL = CRITICAL
    ERROR = logging.ERROR
    NOTICE = logging.INFO + 5
    WARNING = logging.WARNING
    WARN = WARNING
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    NOTSET = logging.NOTSET

    LOG_FACILITY_DAEMON = syslog.LOG_DAEMON
    LOG_FACILITY_USER = syslog.LOG_USER

    LOG_OPTION_NDELAY = syslog.LOG_NDELAY
    LOG_OPTION_PID = syslog.LOG_PID

    LOG_PRIORITY_ERROR = syslog.LOG_ERR
    LOG_PRIORITY_WARNING = syslog.LOG_WARNING
    LOG_PRIORITY_NOTICE = syslog.LOG_NOTICE
    LOG_PRIORITY_INFO = syslog.LOG_INFO
    LOG_PRIORITY_DEBUG = syslog.LOG_DEBUG

    DEFAULT_LOG_FACILITY = LOG_FACILITY_USER
    DEFAULT_LOG_OPTION = LOG_OPTION_NDELAY

    MAX_LOG_FILE_SIZE = 10 * 1024 * 1024
    MAX_LOG_FILE_BACKUP_COUNT = 3

    MAX_MSG_HASH_SIZE = 100
    MAX_MSG_TIMEOUT_HASH_SIZE = 50
    MSG_HASH_TIMEOUT = 60 * 60 * 1000

    def __init__(self, use_syslog=False, ident=None, log_file=None, log_level=INFO, syslog_level=NOTICE):
        """
        @summary:
            The following class provide functionality to log messages.
        @param use_syslog: log also to syslog. Applicable arg
            value 1-enable/0-disable
        @param ident: log identifier
        @param log_file: log to user specified file. Set '' if no log needed
        """
        logging.basicConfig(level=self.DEBUG)
        logging.addLevelName(self.NOTICE, "NOTICE")
        SysLogHandler.priority_map["NOTICE"] = "notice"

        self.logger = logging.getLogger("main")
        self.logger.setLevel(self.DEBUG)
        self.logger.propagate = False
        self.logger_fh = None
        self.logger_emit = True
        self.syslog_hash = {}    # hash array of the messages which was logged to syslog

        self.set_param(use_syslog, ident, log_file, log_level, syslog_level)
        for level in ("debug", "info", "notice", "warn", "error", "critical"):
            setattr(self, level, self._make_log_level(level))

    def __del__(self):
        """
        @summary:
            Cleanup and stop logger
        """      
        self.stop()

    def _make_log_level(self, level):
        level_map = {
            "debug": self.DEBUG,
            "info": self.INFO,
            "notice": self.NOTICE,
            "warn": self.WARNING,
            "warning": self.WARNING,
            "error": self.ERROR,
            "critical": self.CRITICAL,
        }

        def log_method(msg, id=None, repeat=0):
            self.log_handler(level_map[level], msg, id, repeat)
        return log_method

    def init_syslog(self, log_identifier=None, log_facility=DEFAULT_LOG_FACILITY, log_option=DEFAULT_LOG_OPTION, syslog_level=NOTICE):
        """
        @summary:
            Initialize syslog
        @param log_identifier: log identifier
        @param log_facility: log facility
        @param log_option: log option
        @param syslog_level: syslog level
        """

        self._syslog = syslog

        if log_identifier is None:
            log_identifier = os.path.basename(sys.argv[0])

        # Initialize syslog
        self._syslog.openlog(ident=log_identifier, logoption=log_option, facility=log_facility)

        # Set the default minimum log priority to LOG_PRIORITY_NOTICE
        self._syslog_min_log_priority = syslog_level

    def set_param(self, use_syslog=None, ident=None, log_file=None, log_level=INFO, syslog_level=NOTICE):
        """
        @summary:
            Set logger parameters. Can be called any time
            log provided by /lib/lsb/init-functions always turned on
        @param use_syslog: log also to syslog. Applicable arg
            value 1-enable/0-disable
        @param ident: log identifier
        @param log_file: log to user specified file. Set None if no log needed
        """
        if log_file and not isinstance(log_file, str):
            raise ValueError("log_file must be a string")
        
        if log_file and log_file not in ["stdout", "stderr"]:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.access(log_dir, os.W_OK):
                raise PermissionError(f"Cannot write to log directory: {log_dir}")

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        if log_file:
            if any(std_file in log_file for std_file in ["stdout", "stderr"]):
                self.logger_fh = logging.StreamHandler()
            else:
                self.logger_fh = RotatingFileHandler(log_file,
                                                     maxBytes=self.MAX_LOG_FILE_SIZE,
                                                     backupCount=self.MAX_LOG_FILE_BACKUP_COUNT)

            self.logger_fh.setFormatter(formatter)
            self.logger_fh.setLevel(log_level)
            self.logger.addHandler(self.logger_fh)

        if use_syslog:
            self.init_syslog(log_identifier=ident, syslog_level=syslog_level)

    def syslog_log(self, level, msg):
        """
        @summary:
            Log message to syslog
        @param level: log level
        @param msg: message
        """
        if level >= self._syslog_min_log_priority:
            self._syslog.syslog(level, msg)

    def stop(self):
        """
        @summary:
            Cleanup and stop logger
        """
        logging.shutdown()
        handler_list = self.logger.handlers[:]
        for handler in handler_list:
            handler.close()
            self.logger.removeHandler(handler)
        self.logger_emit = False
        self.syslog_hash = {}
        self._syslog.closelog()  # Close syslog

    def close_log_handler(self):
        if self.logger_fh:
            self.logger_fh.flush()
            self.logger_fh.close()
            self.logger.removeHandler(self.logger_fh)

    def set_loglevel(self, verbosity):
        """
        @summary:
            Set log level for logging in file
        @param verbosity: logging level 0 .. 80
        """
        if self.logger_fh:
            self.logger_fh.setLevel(verbosity)

    def log_handler(self, level, msg="", id=None, repeat=0):
        """
        @summary:
            Logs message to both log and syslog.
                1. The message is always logged to log.
                2. Repeated messages can be "collapsed" in syslog:
                - When a repeated message is detected, it will shown only "repeat" times.
                - When the condition clears, a final message with a "clear" marker is logged.
                This helps reduce syslog clutter from frequent, identical messages.
        @param msg: message text
        @param id: unique identifier for the message, used to group and collapse repeats
        @param repeat:  Maximum number of times to log repeated messages to syslog before collapsing.
        """
        # ERROR, WARNING, INFO, NOTICE can be pushed to syslog (optionally)
        if level in [self.ERROR, self.WARNING, self.INFO, self.NOTICE]:
            msg, syslog_emit = self.push_syslog(msg, id, repeat)
        # DEBUG can't be pushed to syslog
        elif level == self.DEBUG:
            syslog_emit = False
        # CRITICAL always push to syslog
        elif level == self.CRITICAL:
            syslog_emit = True
        else:
            raise ValueError(f"Invalid log level: {level}")

        if msg:
            if not self.logger_emit:
                return
            self.logger_emit = False

            try:
                self.logger.log(level, msg)
                if syslog_emit:
                    self.syslog_log(level, msg)
            except (IOError, OSError, ValueError) as e:
                print ("Error logging message: {} {}".format(msg, e))
                pass
            finally:
                self.logger_emit = True

    def syslog_hash_garbage_collect(self):
        """
        @summary:
            Remove from syslog_hash all messages older than 60 minutes or if hash is too big
        """
        hash_size = len(self.syslog_hash)
        self.logger.info("syslog_hash_garbage_collect: hash_size={}".format(hash_size))

        if hash_size > self.MAX_MSG_HASH_SIZE:
            # some major issue. We never expect to have more than 100 messages in hash.
            self.logger.error("syslog_hash_garbage_collect: too many ({}) messages in hash. Remove all messages.".format(hash_size))
            self.syslog_hash = {}
            return

        if hash_size > self.MAX_MSG_TIMEOUT_HASH_SIZE:
            # some messages were not cleaned up.
            # remove messages older than 60 minutes
            current_time = current_milli_time()
            expired_keys = [
                key for key, value in self.syslog_hash.items()
                if value["ts"] < current_time - self.MSG_HASH_TIMEOUT
            ]

            for key in expired_keys:
                self.logger.warning("syslog_hash_garbage_collect: remove message \"{}\" from hash".format(self.syslog_hash[key]["msg"]))
                del self.syslog_hash[key]

    def push_syslog(self, msg="", id=None, repeat=0):
        """
        @param msg: message to save to log
        @param id: id used as key for message that should be "collapsed" into start/stop messages
        @param repeat: max count of the message to display in syslog
        @summary:
            if repeat > 0 then message will be logged to syslog "repeat" times.
            if id == None just print syslog (no start-stop markers)
            if id != None then save to hash, message for log start/stop event
            if repeat is 0 stop syslog emit
            if id == None stop syslog emit
            if id != None syslog emit log with "clear" marker
        @return: message to log, syslog_emit flag
        """

        syslog_emit = False
        id_hash = hash(id) if id else None

        if repeat > 0:
            syslog_emit = True
            if id_hash:
                if id_hash in self.syslog_hash:
                    self.syslog_hash[id_hash]["count"] += 1
                    self.syslog_hash[id_hash]["msg"] = msg
                else:
                    self.syslog_hash_garbage_collect()
                    self.syslog_hash[id_hash] = {"count": 1, "msg": msg, "ts": current_milli_time()}

                self.syslog_hash[id_hash]["ts"] = current_milli_time()

                if self.syslog_hash[id_hash]["count"] > repeat:
                    syslog_emit = False
        else:
            # message in hash - print to syslog last time
            if id_hash in self.syslog_hash:
                # new message not defined - use message from hash
                if not msg:
                    msg = self.syslog_hash[id_hash]["msg"]
                    # add "finalization" mark to message
                    if self.syslog_hash[id_hash]["count"] > 1:
                        msg = "message repeated {} times: [ {} ] and stopped".format(self.syslog_hash[id_hash]["count"], msg)

                # remove message from hash
                del self.syslog_hash[id_hash]
                syslog_emit = True
        return msg, syslog_emit


class RepeatedTimer(object):
    """
    @summary:
        Provide repeat timer service. Can start provided function with selected  interval
    """

    def __init__(self, interval, function):
        """
        @summary:
            Create timer object which run function in separate thread
            Automatically start timer after init
        @param interval: Interval in seconds to run function
        @param function: function name to run
        """
        self._timer = None
        self.interval = interval
        self.function = function

        self.is_running = False
        self.start()

    def _run(self):
        """
        @summary:
            wrapper to run function
        """
        self.is_running = False
        self.start()
        self.function()

    def start(self, immediately_run=False):
        """
        @summary:
            Start selected timer (if it not running)
        """
        if immediately_run:
            self.function()
            self.stop()

        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        """
        @summary:
            Stop selected timer (if it started before)
        """
        self._timer.cancel()
        self.is_running = False
