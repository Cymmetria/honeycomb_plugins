.. include:: ../README.rst

.. toctree::
    :maxdepth: 3
    :hidden:

    service_api
    integration_api
    honeycomb_commands


Writing your first plugin
=========================

Using simple_http as an example to accompany this guide, we will describe the 4 steps necessary to write a plugin.
Feel free to use the provided config.json as a base for your own, and modify fields as required. It is recommended,
for the sake of organization, that you create a new directory and follow this guide inside your specific plugin's
directory.

.. note::
    If you're looking for the full documentation for Honeycomb_ API look at :mod:`.base_service` and
    :mod:`.integration_utils`

Plugin configuration - config.json
==================================

The config.json file describes the possible parameters your service can receive, and alerts it can emit.
simple_http's config.json looks like this:

.. literalinclude:: ../services/simple_http/config.json
    :name: config.json
    :linenos:
    :caption: config.json

The *event_types* field describes alerts. This is the most important part of the configuration,
as it's the way Honeycomb detects and logs suspicious events. There can be multiple alerts for each honeypot,
as long as each alert is described by this structure.

Let's break down the structure:

:name: This is the internal identifier of the alert. Your python script should emit an alert matching *name* in order
       for it to be recognized and formatted.
:label: Human-readable name of the alert. This is the description of the alert.
:fields: An alert can take any number of parameters and output them when it triggers. This describes the parameters it
         takes.
:policy: This can be "Alert" or "Mute", for future use.

Next, we'll look at the *service* field. It describes the service generally and is used to avoid conflicts between
honeypots that run simultaneously:

:allow_many: Allow multiple instances of this honeypot?
:supported_os_families: This prevents OS-specific honeypots from being installed on the wrong system. Current valid
                        values are "Linux", "Windows", "Darwin", and "All".
:ports: Any ports this honeypot uses. For simple_http, you would expect port 80, but the service actually takes its
        port as a parameter.
:name: Internal service name.
:label: Human readable name.
:description: Full fledged description of the service.
:conflicts_with: Specific honeypots that this one conflicts with for whatever reason. You don't have to fill this field
                 in, but if you know of conflicts you should.

And finally, the *parameters* field describes optional and non-optional parameters that your service can receive.
Each parameter is described as follows:

:type: The json type of the parameter.
:value: Parameter name.
:label: Parameter description.
:required: Set to *true* if parameter is mandatory, or *false* if optional.
:default: Default value.

Honeypot logic
==============

Filename
--------

Create a python file and name it *(honeypot_name)_service.py*. For example: *simple_http_service.py*.

Imports
-------

Add the following import at the top of your service module:

.. code-block:: python

    from base_service import ServerCustomService

Plugin logic
------------

Create your plugin by defining a class that inherits from :class:`.base_service.ServerCustomService`, for example:

.. code-block:: python

    class SimpleHTTPService(ServerCustomService):

We will address most of :class:`.ServerCustomService`'s API but make sure to also review its documentation for
additional help. For example, it contains its own logger which is configured to record logs accross the framework.

Entry and exit
--------------

Your entry point will be the :meth:`.on_server_start` method. If you need an exit and cleanup point,
that's :meth:`.on_server_shutdown`.

.. literalinclude:: ../services/simple_http/simple_http_service.py
    :name: SimpleHTTPService.on_server_start
    :linenos:
    :caption: SimpleHTTPService.on_server_start
    :pyobject: SimpleHTTPService.on_server_start


.. literalinclude:: ../services/simple_http/simple_http_service.py
    :name: SimpleHTTPService.on_server_shutdown
    :linenos:
    :caption: SimpleHTTPService.on_server_shutdown
    :pyobject: SimpleHTTPService.on_server_shutdown

.. note::

    :meth:`.on_server_start` **must** call :meth:`.signal_ready` to let the framework know it has successfully
    initialized and started working.

In simple_http, once we call :meth:`.on_server_shutdown`, execution flows into an infinite loop and so we must call
:meth:`.on_server_shutdown` beforehand.

Parameters
----------

If your service receives parameters, you can access them via service_args, supplying it with the
*parameter value* from before.
For example, in simple_http:

.. code-block:: python

    port = self.service_args.get('port', DEFAULT_PORT)

Connecting the plugin
---------------------

Your `__main__` should consist of only one line:

.. code-block:: python

    service_class = (your_plugin_class_name)

For example, in simple_http:

.. code-block:: python

    service_class = SimpleHTTPService


Reporting alerts
----------------

The last vital stage in writing a useful plugin for Honeycomb is making it actually trigger alerts in case something
bad happens. For this, :meth:`.add_alert_to_queue` is your method of choice. Supply it with a single parameter,
a dictionary containing all the fields described in the alert as defined in your config.json, and *event_name*
should contain the alert name. For example, simple_http defined one alert called *simple_http*, containing three fields:
"originating_ip", "originating_port", and "request". A matching alert may look like this:

.. code-block:: python

    self.add_alert_to_queue({
        "event_type" : "simple_http",
        "originating_ip" : client.ip,
        "originating_port" : client.port,
        "request" : request.content
    })


Test your service
-----------------

It is recommended you override the :meth:`.test()`` method in your plugin class that returns triggers your alerts and
returns a list to verify. The framework will automatically execute your test method and make sure all the listed
alerts have been triggered successfully.

External Requirements
---------------------------

If your service depends on external modules, you can add them to a requirements.txt and the framework will install them
in a virtual environment that will be loaded with you run the service.

It is recommended that you take simple_http as a skeleton of a service and modify it as necessary for your first
honeypot. To install your new honeypot, 'honeycomb service install (directoryname)' on the chosen plugin directory,
followed by 'honeycomb service run (pluginname)'. For more commands,
read http://honeycomb.cymmetria.com/en/latest/cli.html#honeycomb-service.

Have fun!
