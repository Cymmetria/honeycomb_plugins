# -*- coding: utf-8 -*-
"""Universal Honeypot
Author: Matt Carothers https://github.com/MattCarothers/uhp

Universal Honey Pot is a medium interaction honeypot that allows defenders to
quickly implement line-based TCP protocols with a simple JSON configuration.

## Why?
Threats evolve quickly, and writing traditional honeypots is a pain.  Defenders
start from scratch writing networking, logging, and protocol emulation code,
and then they still have to integrate their new honeypot with existing systems.
In practice, few new honeypots ever get written for those reasons.

UHP provides all the networking and logging, and it outputs JSON or publishes
to hpfeeds for quick integration.  It makes emulating new protocols a simple
matter of creating some JSON, or it can even run with a generic config and
write new skeleton emulations all by itself based on the input it receives.

## Configuration
The UHP basic configuration contains two data elements:
* banner - (optional) UHP provides this text to every connecting client.
* states - The list of machine states and the rules to transition between them.

Each state contains a list of transition rules.  A transition rule has three
basic elements, all of which are optional:
* pattern - A regular expression.  The machine executes the first matching rule.
* output - This text will be returned to the client if the pattern  matches.
* next - The new state for the machine to enter on a match.  If no
         next state is provided, the machine remains in its current state.

There are three special states:

* _START - Every machine starts in this state, and it must be defined.
* _SHARED - (optional) The _SHARED state is for common transition rules that
            apply to all states.  If no rules in a given state fire, the machine
            next checks all the rules in the _SHARED state.
* _END - Transitioning to the _END state signals UHP to close the
         connection.

## Example Configuration
This JSON implements a POP3 honeypot:
```
{
    "banner" : "+OK Ready\r\n",
    "states" : {
        "_START" : [
            {
                "pattern" : "^PASS",
                "output"  : "-ERR No username given.\r\n"
            }
        ],
        "user_accepted" : [
            {
                "pattern" : "^PASS",
                "output"  : "-ERR invalid user name or password.\r\n",
                "next"    : "_END"
            }
        ],
        "_SHARED" : [
            {
                "pattern" : "^USER",
                "output"  : "+OK\r\n",
                "next"    : "user_accepted"
            },
            {
                "pattern" : "^QUIT",
                "output"  : "+OK Logging out\r\n",
                "next"    : "_END"
            },
            {
                "pattern" : ".",
                "output"  : "-ERR Unknown command.\r\n"
            }
        ]
    }
}
```
Additional elements (see Dynamic Output and Advanced Configuration below):
* match_case - (rule) This flag makes the regex match case sensitive.
* tags - (rule/global) An array of tags to add to the log
* fields - (rule/global) A dictionary of keys and values to add to the log
* datefmt - (rule/global) a strftime() string to format the {date} output

## Dynamic Output
If a transition rule pattern contains groupings, matches can be used in output.
Example rule:
```
{
    "pattern" : "^HELO (\\S+)",
    "output"  : "250 localhost.localdomain pleased to meet you, {match[0]}\r\n",
    "next"    : "helo_accepted"
}
```
Named subgroups work as well:
```
{
    "pattern" : "^EHLO (?P<hostname>\\S+)",
    "output"  : "250 localhost.localdomain pleased to meet you, {hostname}\r\n",
    "next"    : "helo_accepted"
}
```
Note that the JSON parser treats back slashes as escape characters, so double
back slashes must be used for regular expressions.

Additionally, a field name called {date} contains the current date and time.
Set "datefmt" in the server config or in an individual transition rule to
control the format.
Examples:
```
{
    "states" : {
        "_START" : [
            {
                "pattern" : "^(GET|POST|HEAD|PUT|DELETE)",
                "output"  : "HTTP/1.1 404 Not Found\r\nServer: nginx/1.13.4\r\nDate: {date}\r\n",
                "datefmt" : "%a, %d %b %Y %H:%M:%S GMT",
                "next"    : "_END"
            }
        ]
    }
}
```
```
{
    "banner" : "It's {date}.  Do you know where your children are?",
    "datefmt" : "%Y-%m-%dT%H:%M:%SZ",
    "states" : {
        "_START" : [ ]
    }
}
```
## Advanced Configuration
You may wish to set custom fields in the JSON output or override the defaults.
You may do so by adding a "fields" dictionary either globally or as part of a
specific rule.  Example:
```
{
    "datefmt" : "%a, %d %b %Y %H:%M:%S GMT",
    "fields"  : {
        "app"      : "uhp",
        "emulated" : "nginx"
    },
	"states" : {
		"_START" : [
			{
				"pattern" : "^(GET|POST|PUT|DELETE|HEAD|OPTIONS)( .*)",
                "fields"  : {
                    "uri"  : "{match[0]}{match[1]}"
                },
				"next"    : "valid_command"
			},
            {
                "pattern" : ".",
				"output"  : "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.13.4\r\nDate: {date}\r\nConnection: close\r\n",
                "next"    : "_END"
            }
		],
        "valid_command" : [
			{
				"pattern" : "^User-Agent: ?(.*)",
                "fields"  : {
                    "ua"  : "{match[0]}"
                }
			},
            {
                "pattern" : "^$",
				"output"  : "HTTP/1.1 404 Not Found\r\nServer: nginx/1.13.4\r\nDate: {date}\r\nConnection: close\r\n",
                "next"    : "_END"
            }
        ]
	}
}
```
Note that fields persist per session, so a field you set in one state will
continue to be logged in future states.  Also note that you can use this to
override built in fields.  For example, this hides your honeypot's ip address:
```
{
    "fields" : {
        "dest_ip" : "0.0.0.0"
    },
    "states" : {
        "_START" : [ ]
    }
}
```
## Auto Config Generation
Using the -a flag, UHP can automatically generate new state machines
based on client input.  Each line supplied by the client creates a new state,
and the machine writes the new configuration at the end of the session.  The new
configuration file will be named *SourceIP*-*DestPort*-*MD5ofInput*.

You may wish to ignore certain input lines that you expect to vary from client
to client or server to server in order to make the signatures more general.  Do
do so, add the "am_ignore" tag to the transition rule you wish the machine to
ignore.  Here is an example configuration that logs input until a blank line is
received and ignores Host headers:

```
{
    "states" : {
        "_START" : [
            {
                "pattern" : "^Host:",
                "tags"    : [ "am_ignore" ]
            },
            {
                "pattern" : "^$",
                "next"    : "_END"
            }
        ]
    }
}
```
This is a new skeleton machine generated by running curl against the above
configuration:
```
{
    "states": {
        "_START": [
            {
                "next": "1",
                "pattern": "GET / HTTP/1.1"
            }
        ],
        "1": [
            {
                "next": "2",
                "pattern": "User-Agent: curl/7.47.0"
            }
        ],
        "2": [
            {
                "next": "3",
                "pattern": "Accept: */*"
            }
        ],
        "3": [
            {
                "next": "_END",
                "pattern": ""
            }
        ]
    }
}
```
"""

import re
import sys
import copy
import time
import json
import socket
import hashlib
import threading
import socketserver
import configparser

from datetime import datetime
from uuid import uuid4


class UHPEvent():
    def __init__(self, src_ip, src_port, dest_ip, dest_port, action, message, tags=[], fields={}, session_id=None, signature=None):
        # Network info
        self.src_ip     = src_ip
        self.src_port   = src_port
        self.dest_ip    = dest_ip
        self.dest_port  = dest_port
        # Session ID for the machine
        self.session_id = session_id
        # Event action (connect, disconnect, send, recv, noop)
        self.action  = action
        # Text we sent or received
        self.message = message
        # Tags set by a machine or a rule
        self.tags    = tags
        # ConfigGenerator signature
        if signature:
            self.signature = signature
        # Additional fields added by a machine or rule
        for key, value in fields.items():
            setattr(self, key, value)

    def __repr__(self):
        return("{src_ip}:{src_port} -> {dest_ip}:{dest_port} {action:<10} {tags} {message}".format(**self.__dict__))


class UniversalHoneyPot():
    def __init__(self, config):
        """Construct a Universal Honeypot

        :param dict config: Configuration for the state machine, including the initial banner, state transition rules,
                            and text to return to the client.
        """

        # All machines start in _START
        self.state = "_START"
        self.config = config
        self.states = config['states']

        # Do we have any global tags?
        if "tags" in config:
            self.tags = config['tags']
        else:
            self.tags = []

        # Do we have any custom fields?
        if "fields" in config:
            self.fields = config['fields']
        else:
            self.fields = {}

        # Create a default empty shared state
        if "_SHARED" not in self.states:
            self.states['_SHARED'] = []

        if "banner" in config:
            self.banner = config['banner']
        else:
            self.banner = None

        # Set a unique ID for this session so we can track related logs
        self.session_id = str(uuid4())

        # Signatures are md5 hashes of input text created by a ConfigGenerator
        self.signature = None

    def run(self, input_):
        """Change states based on input.

        :return: The output associated with the state change.
        """
        # Iterate through the transition rules for this state
        for rule in self.states[self.state] + self.states['_SHARED']:
            # Does the pattern match?
            if "match_case" in rule and rule['match_case']:
                m = re.search(rule['pattern'], input_)
            else:
                m = re.search(rule['pattern'], input_, re.IGNORECASE)
            if m:
                # The pattern matches, so transition to our next state if one
                # was provided.  A rule without a "next" stays in the same
                # state but still returns output.
                if "next" in rule:
                    self.state = rule['next']
                    logger.debug("'{}' matched /{}/ | {} -> {}".format(
                        input_, rule['pattern'], self.state, rule['next'])
                    )
                else:
                    logger.debug("'{}' matched /{}/ | {} -> {}".format(
                        input_, rule['pattern'], self.state, self.state)
                    )
                # Add a {date} key for output
                dt = datetime.utcnow()
                output_fields = {}
                if "datefmt" in rule:
                    date = dt.strftime(rule['datefmt'])
                elif "datefmt" in self.config:
                    date = dt.strftime(self.config['datefmt'])
                else:
                    date = str(dt)
                output_fields['date'] = date

                # Add regex matches.  These can be accessed in the rule output
                # as {match[0]} ... {match[N]}
                output_fields['match'] = m.groups()

                # The output might be a format string expecting matches
                # from the regex.
                try:
                    # Catch this exception in case the format string has more
                    # replacement fields than there were matches.
                    # Include m.groupdict() as well for named parameters. E.g.
                    #     "pattern" : "^USER (?P<username>.*),
                    #     "output"  : "Hello, {username}"
                    output = rule['output'].format(**output_fields, **m.groupdict())
                except IndexError:
                    if "output" in rule:
                        output = rule['output']
                    else:
                        output = None

                # Do we have tags to apply?
                tags = self.tags
                if "tags" in rule:
                    tags = tags + rule['tags']

                # Do we need to add additional fields?
                if "fields" in rule:
                    for key, value in rule['fields'].items():
                        # Add the fields to our machine so they persist
                        # between states
                        self.fields[key] = value.format(**output_fields)

                return(output, tags, self.fields)
            else:
                logger.debug("'{}' did not match /{}/ | {} -> {}".format(
                    input_, rule['pattern'], self.state, self.state))
        # No rules matched
        logger.debug("'{}' did not match any patterns | {} -> {}".format(
            input_, self.state, self.state))
        return(None, self.tags, self.fields)

    @staticmethod
    def validate(config):
        # Validate our config
        if "states" not in config:
            raise RuntimeError("No states defined in config")
        states = config['states']
        if not isinstance(states, dict):
            raise RuntimeError("'states' should be a hash")
        if "_START" not in states:
            raise RuntimeError("No _START state defined in config")
        for state in states:
            for rule in states[state]:
                if "tags" in rule and not isinstance(rule['tags'], list):
                    raise RuntimeError("Tags should be an array of strings")
                if "next" in rule and rule['next'] != "_END" and rule['next'] not in states:
                    raise RuntimeError("Rule next value '%s' points to a non-existent state" % (rule['next']))

class ConfigGenerator():
    """
    ConfigGenerator is an object that dynamically constructs a UniversalHoneyPot
    configuration file based on client input.
    """
    def __init__(self, server):
        self.state     = 0
        self.hash      = hashlib.md5()
        self.config    = { 'states' : { } }
        self.directory = server.server.auto_machine_dir
        self.src_ip    = server.src_ip
        self.src_port  = server.src_port
        self.dest_ip   = server.dest_ip
        self.dest_port = server.dest_port

    def advance(self, pattern):
        # If we're in state 0, use "_START_ instead
        current_state = self.state or "_START"
        self.config['states'][str(current_state)] = [
            { 'pattern' : pattern, 'next' : str(self.state + 1) }
        ]
        self.state = self.state + 1
        self.hash.update(bytes(pattern, 'utf8'))

    def write(self):
	# If we didn't get any input, there's nothing to do
        if not self.state:
            return
        # Create a filename based on source ip, dest port, and the
        # hash of the input
        filename = '-'.join([
            self.src_ip, str(self.dest_port), self.hash.hexdigest()
        ])
        # Rewrite the last state's next to _END
        if self.state == 1:
            self.config['states']['_START'][0]['next'] = "_END"
        else:
            self.config['states'][str(self.state - 1)][0]['next'] = "_END"
        with open(self.directory + '/' + filename, 'w') as f:
            f.write(json.dumps(self.config, sort_keys=True, indent=4))
            f.write("\n")
            logger.debug("Wrote " + self.directory + '/' + filename)

###################
# Server routines #
###################

class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        """
        @summary: Handle a TCP connection.  Read from the client until
                  it disconnects or our state machine reaches _END state.
        """
        # Store connection information here because later calls to
        # getpeername() and getsockname() can raise an OSError
        try:
            self.src_ip,  self.src_port  = self.connection.getpeername()
            self.dest_ip, self.dest_port = self.connection.getsockname()
        except:
            return
        # Intialize two variables to hold all the text send and received.
        # We'll used this if server.config.log_sessions is true and we're
        # logging entire sessions instead of individual lines.
        self.session_send = ""
        self.session_recv = ""
        # Initialize the state machine
        machine = UniversalHoneyPot(self.server.config)
        self.log("connect", machine=machine)

        # Initialize the auto machine generator if needed
        if self.server.auto_machine_dir:
            config_generator = ConfigGenerator(self)

        # Write out the banner if there is one
        if machine.banner:
            # Set up the date so we can output it in the banner if needed
            dt = datetime.utcnow()
            if "datefmt" in self.server.config:
                date = dt.strftime(self.server.config['datefmt'])
            else:
                date = str(dt)
            banner = machine.banner.format(**{ 'date' : date })
            self.wfile.write(bytes(banner, 'utf8'))
            if self.server.log_replies:
                self.log("send", banner, machine=machine)

        # Keep track of bytes received so we can truncate if -m is set
        bytes_remaining = self.server.max_bytes

        # Loop as long as there's input
        try:
            for line in self.rfile:
                if not line:
                    break
                try:
                    line = line.decode('utf8')
                except:
                    continue

                # Check to see if we've exceeded max bytes, and truncate if so
                if server.max_bytes:
                    if len(line) > bytes_remaining:
                        line = line[0:bytes_remaining]
                        machine.truncated = True
                    # Subtract this line's bytes from the amount remaining. If it's
                    # <= 0, we'll terminate the session after running the machine.
                    bytes_remaining = bytes_remaining - len(line)

                # Run the machine on the input, and return the output to the client
                output, tags, fields = machine.run(line.rstrip())
                self.log("recv", line, tags, fields, machine=machine)
                # Did the machine produce output to send back to the client?
                if output:
                    self.wfile.write(bytes(output, 'utf8'))

                # Are we configured to log the replies we send back to clients?
                if self.server.log_replies:
                    if output:
                        self.log("send", output.rstrip(), tags, fields, machine=machine)
                    else:
                        self.log("noop", output, tags, fields, machine=machine)

                # Advance the config generator if needed
                if self.server.auto_machine_dir and "am_ignore" not in tags:
                    config_generator.advance(line.rstrip())

                # End the session if max_bytes is set and we've exceeded the limit
                if self.server.max_bytes and bytes_remaining <= 0:
                    break

                # Machine state _END means we're done
                if machine.state == "_END":
                    break
        except:
            pass

        # Clean up by logging the disconnect and writing out our new auto config
        if self.server.auto_machine_dir:
            config_generator.write()
            machine.signature = config_generator.hash.hexdigest()
        self.log("disconnect", machine=machine)

    def log(self, action, message="", tags=[], fields={}, session_id=None, machine=None):
        """
        @summary: log output
        """
        tags       = tags or machine.tags
        fields     = fields or machine.fields
        session_id = session_id or machine.session_id
        # Are we configured to log entire sessions in one event?
        # If so, store sends and receives for later, and emit a
        # log on disconnect.
        if self.server.log_sessions:
            if action == "send":
                self.session_send = self.session_send + message
            elif action == "recv":
                self.session_recv = self.session_recv + message
            elif action == "disconnect":
                event = UHPEvent(
                    self.src_ip, self.src_port,
                    self.dest_ip, self.dest_port,
                    "recv", self.session_recv, tags,
                    fields, session_id, machine.signature
                )
                logger.warn(event)
                # Send a second event for the transmitted data if configured
                # to do so.
                if self.server.log_replies:
                    event = UHPEvent(
                        self.src_ip, self.src_port,
                        self.dest_ip, self.dest_port,
                        "send", self.session_send, tags,
                        fields, session_id, machine.signature
                    )
                    logger.warn(event)
        else:
            event = UHPEvent(
                self.src_ip, self.src_port,
                self.dest_ip, self.dest_port,
                action, message.rstrip(), tags,
                fields, session_id, machine.signature
            )
            logger.warn(event)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class JSONFormatter(logging.Formatter):
    """
    @summary: logging Formatter to emit JSON records
    """
    def __init__(self, timestamp_field="timestamp", *args, **kwargs):
        self.timestamp_field = timestamp_field
        self.converter = time.gmtime
        super().__init__(*args, **kwargs)

    def format(self, record):
        record = copy.copy(record)
        # Create a dict from the message and add a timestamp to it
        try:
            msg = record.msg.__dict__
            msg.pop('fields', None)
        except:
            msg = { 'message' : record.msg }
        dt = datetime.fromtimestamp(record.created)
        msg[self.timestamp_field] = dt.strftime(self.datefmt)
        # Remove the message field if it's empty
        if "message" in msg and msg['message'] == None:
            msg.pop('message', None)
        # Turn the message into JSON
        record.msg = json.dumps(msg)
        return super().format(record)

# Filter to make sure only info goes to the JSON log file
class OnlyWarnFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno == logging.WARN

class HPFeedsHandler(logging.Handler):
    def __init__(self, host, port, channel, ident, secret):
        self.channel = channel
        # Ref https://github.com/threatstream/hpfeeds-collector
        try:
            self.publisher = hpfeeds.new(host, port, ident, secret)
        except hpfeeds.FeedException as e:
            logger.error("Feed exception: %s" % e)
            sys.exit(1)
        logger.debug("Connected to %s (%s:%s)" % (self.publisher.brokername, host, port))
        super().__init__()

    def emit(self, record):
        msg = self.format(record)
        self.publisher.publish(self.channel, msg)
        logger.debug("HPF: sent" + msg)

if __name__ == "__main__":
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("config_file", help="Config file")
    parser.add_argument("port", help="bind port", type=int, nargs='+')
    parser.add_argument("-b", "--bind-host", help="bind host (defaults to 0.0.0.0)",
            default="0.0.0.0")
    parser.add_argument("-H", "--hpfeeds-config", help="config file for hpfeeds logging")
    parser.add_argument("-f", "--file", help="log file (JSON)")
    parser.add_argument("-a", "--auto-machine-dir",
            help="directory to write auto machine configs", default=None)
    parser.add_argument("-m", "--max-bytes", type=int,
            help="maximum bytes to log per session", default=0)
    parser.add_argument("-v", "--verbose", help="output debugging information",
            default=False, action="store_true")
    parser.add_argument("-q", "--quiet", help="suppress stdout log output",
            default=False, action="store_true")
    parser.add_argument("-r", "--log-replies", help="log what we return to clients",
            default=False, action="store_true")
    parser.add_argument("-j", "--json", help="log JSON to stdout",
            default=False, action="store_true")
    parser.add_argument("-s", "--log-sessions",
            help="log sessions as single events rather than one event per line",
            default=False, action="store_true")
    args = parser.parse_args()

    # Configure logging
    logger.setLevel(logging.DEBUG)
    stdout_handler = logging.StreamHandler()

    # Output formatter for plain text
    plain_formatter = logging.Formatter(
        '%(asctime)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z'
    )

    # Output formatter for JSON
    json_formatter = JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%SZ', timestamp_field='@timestamp')

    # Should stdout be JSON or plain text?
    if args.json:
        stdout_handler.setFormatter(json_formatter)
    else:
        stdout_handler.setFormatter(plain_formatter)

    # Check for verbose/quiet
    if not args.quiet:
        if args.verbose:
            stdout_handler.setLevel(logging.DEBUG)
        else:
            stdout_handler.setLevel(logging.INFO)
        logger.addHandler(stdout_handler)

    # Do we have an output file?
    if args.file:
        file_handler = logging.handlers.TimedRotatingFileHandler(
                args.file,
                when='midnight',
                interval=1,
                backupCount=7
        )
        file_handler.setFormatter(json_formatter)
        # Only log info() to this handler
        file_handler.addFilter(OnlyWarnFilter())
        logger.addHandler(file_handler)

    # Enable hpfeeds?
    if args.hpfeeds_config:
        config = configparser.ConfigParser()
        config.read(args.hpfeeds_config)
        hpf = config['hpfeeds']
        hpf_handler = HPFeedsHandler(
            hpf['host'],
            int(hpf['port']),
            hpf['channel'],
            hpf['ident'],
            hpf['secret']
        )
        hpf_handler.setFormatter(json_formatter)
        hpf_handler.setLevel(logging.WARN)
        logger.addHandler(hpf_handler)

    # Read in the config file that defines state transitions
    with open(args.config_file) as f:
        config = json.loads(f.read())

    # Check the config for errors
    UniversalHoneyPot.validate(config)

    ThreadedTCPServer.allow_reuse_address = True
    for port in args.port:
        server = ThreadedTCPServer((args.bind_host, port), ThreadedTCPRequestHandler)
        ip, port = server.server_address
        # Pass some configuration data to the server object
        server.config = config
        server.log_replies  = args.log_replies
        server.log_sessions = args.log_sessions
        server.auto_machine_dir = args.auto_machine_dir
        server.max_bytes = args.max_bytes
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info("Listening on {}:{}".format(ip, port))

    while True:
        time.sleep(1)
