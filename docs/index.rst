.. include:: ../README.rst

====================
Honeycomb Plugin API
====================

If you're looking for the full documentation for Honeycomb_ API you can find it at
:module:`honeycomb.servicemanager.base_service` and :module:`honeycomb.integrationmanager.integration_utils`


=========================
Writing your first plugin
=========================

Using simple_http as an example to accompany this guide, we will describe the 3 steps necessary to write a plugin.
Feel free to use the provided config.json as a base for your own, and modify fields as required. It is recommended,
for the sake of organization, that you create a new directory and follow this guide inside your specific plugin's directory.

1. Plugin configuration - config.json
=====================================

The config.json file describes the possible parameters your service can receive, and alerts it can emit.
simple_http's config.json looks like this:

.. literalinclude:: ../services/simple_http/config.json
    :caption: config.json
    :name: config-json
    :linenos:

The *event_types* field describes alerts. This is the most important part of the configuration,
as it's the way Honeycomb detects and logs suspicious events. There can be multiple alerts for each honeypot,
as long as each alert is described by this structure.

Let's break down the structure:

:name: This is the internal identifier of the alert. Your python script should emit an alert matching *name* in order for it to be recognized and formatted.
:label: Human-readable name of the alert. This is the description of the alert.
:fields: An alert can take any number of parameters and output them when it triggers. This describes the parameters it takes.
:policy: This can be "Alert" or "Mute", for future use.

Next, we'll look at the *service* field. It describes the service generally and is used to avoid conflicts between
honeypots that run simultaneously:

:allow_many: Allow multiple instances of this honeypot?
:supported_os_families: To prevent OS-specific honeypots from being installed on the wrong system. Current valid values are "Linux", "Windows", "Darwin", and "All".
:ports: Any ports this honeypot uses. For simple_http, you would expect port 80 here, but the service actually takes its port as a parameter.
:name: Internal service name.
:label: Human readable name.
:description: Full fledged description of the service.
:conflicts_with: Specific honeypots that this one conflicts with for whatever reason. You don't have to fill this field in, but if you know of conflicts you could.

And finally, the *parameters* field describes optional and non-optional parameters that your service can receive. Each parameter is described as follows:

:type: The json type of the parameter.
:value: Parameter name.
:label: Parameter description.
:required: Set to *true* if nonoptional, or *false* if optional.
:default: Default value.

2. Honeypot logic
=================

2.1. Filename
-------------
Create a python file and name it *(honeypot_name)_service.py*. For example: *simple_http_service.py*.

2.2. Imports
------------
Add the following import to your honeypot:

.. code-block:: python

    from base_service import ServerCustomService

2.3. Plugin logic
-----------------
Create your plugin by defining a class that inherits from *ServerCustomService*, for example:

.. code-block:: python

    class SimpleHTTPService(ServerCustomService):

To see the full extent of the class, read its documentation here: http://honeycomb.cymmetria.com/en/latest/honeycomb.servicemanager.html
It's noteworthy to mention that it contains its own logger which you can use for debugging or informational purposes.

2.4. Entry and exit
-------------------
Your entry point will be the *on_server_start* method. If you need an exit and cleanup point, that's *on_server_shutdown*.
Note that *on_server_start* _must_ call signal_ready() to let the framework know it has successfully initialized and started working.
Looking at simple_http as an example:

.. code-block:: python

    self.signal_ready()
    self.logger.info("Starting {}Simple HTTP service on port: {}".format('Threading ' if threading else '', port))
    self.httpd.serve_forever()

In simple_http, once we call serve_forever(), execution flows into an infinite loop and so we must signal_ready() beforehand.

*on_server_shutdown* doesn't have to contain anything.

2.5. Parameters
---------------
If your service receives parameters, you can access them via *service_args.get()*, supplying it with the *parameter value* from before.
For example, in simple_http:

.. code-block:: python

    port = self.service_args.get('port', DEFAULT_PORT)

2.6. Connecting the plugin
--------------------------
Your _main_ should consist of only one line:

.. code-block:: python

    service_class = (your plugin class name)

For example, in simple_http:

.. code-block:: python

    service_class = SimpleHTTPService


3. Reporting alerts
-------------------
The last vital stage in writing a useful plugin for Honeycomb is making it actually trigger alerts in case something bad happens.
For this, *add_alert_to_queue()* is your method of choice. Supply it with a single parameter, a dictionary containing all the fields
described in the alert as defined in your config.json, and *event_name* should contain the alert name. For example, since simple_http defined
one alert called __simple_http__, containing three fields: "originating_ip", "originating_port", and "request". A matching alert may look like this:

.. code-block:: python

    self.add_alert_to_queue({
        "event_type" : "simple_http",
        "originating_ip" : client.ip,
        "originating_port" : client.port,
        "request" : request.content
    })



4. Automatic tests
------------------
If you wish, you can define a *test()* method in your plugin class that must return a list of alert names AND trigger them. The framework can then
automatically execute your test method and make sure all the listed alerts have been triggered successfully.

5. (optional) requirements.txt
------------------------------
If your honeypot imports non-standard packages, you can add them to a requirements.txt and the framework will take care of their installation as with pip.

It is recommended that you take simple_http as a skeleton of a service and modify it as necessary for your first honeypot.
To install your new honeypot, 'honeycomb service install (directoryname)' on the chosen plugin directory, followed by
'honeycomb service run (pluginname)'. For more commands, read http://honeycomb.cymmetria.com/en/latest/cli.html#honeycomb-service.

Have fun!
