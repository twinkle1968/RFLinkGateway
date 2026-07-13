import json
import logging
import re


class HADiscovery:
    """Builds Home Assistant MQTT Discovery configuration payloads for RFLink
    devices/parameters.

    Home Assistant listens on `<discovery_prefix>/<component>/<node_id>/<object_id>/config`
    (default discovery_prefix = "homeassistant"). Publishing a retained JSON
    payload there makes the entity appear automatically; publishing an empty
    payload removes it again.

    See: https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery
    """

    # Mapping of RFLink parameter -> Home Assistant entity description.
    #
    # component     : HA platform (sensor / binary_sensor / switch)
    # name          : friendly entity name (device name is prefixed by HA)
    # device_class  : HA device class (drives icon/unit/UI behaviour)
    # unit          : unit_of_measurement
    # state_class   : long term statistics behaviour (measurement / total_increasing)
    # payload_on    : value that means "on" (binary_sensor / switch)
    # payload_off   : value that means "off" (binary_sensor / switch)
    PARAM_MAP = {
        # --- Temperatures (signed, value / 10, °C) ---
        'TEMP':       {'component': 'sensor', 'name': 'Temperature',        'device_class': 'temperature',     'unit': '°C',  'state_class': 'measurement'},
        'WINCHL':     {'component': 'sensor', 'name': 'Wind chill',          'device_class': 'temperature',     'unit': '°C',  'state_class': 'measurement'},
        'WINTMP':     {'component': 'sensor', 'name': 'Wind temperature',    'device_class': 'temperature',     'unit': '°C',  'state_class': 'measurement'},

        # --- Humidity / air ---
        'HUM':        {'component': 'sensor', 'name': 'Humidity',            'device_class': 'humidity',        'unit': '%',   'state_class': 'measurement'},
        'BARO':       {'component': 'sensor', 'name': 'Pressure',            'device_class': 'atmospheric_pressure', 'unit': 'hPa', 'state_class': 'measurement'},
        'CO2':        {'component': 'sensor', 'name': 'CO2',                 'device_class': 'carbon_dioxide',  'unit': 'ppm', 'state_class': 'measurement'},
        'HSTATUS':    {'component': 'sensor', 'name': 'Humidity status'},
        'BFORECAST':  {'component': 'sensor', 'name': 'Forecast'},

        # --- Light / UV ---
        'UV':         {'component': 'sensor', 'name': 'UV index',            'state_class': 'measurement'},
        'LUX':        {'component': 'sensor', 'name': 'Illuminance',         'device_class': 'illuminance',     'unit': 'lx',  'state_class': 'measurement'},

        # --- Rain ---
        'RAIN':       {'component': 'sensor', 'name': 'Rain total',          'device_class': 'precipitation',   'unit': 'mm',  'state_class': 'total_increasing'},
        'RAINRATE':   {'component': 'sensor', 'name': 'Rain rate',           'device_class': 'precipitation_intensity', 'unit': 'mm/h', 'state_class': 'measurement'},

        # --- Wind ---
        'WINSP':      {'component': 'sensor', 'name': 'Wind speed',          'device_class': 'wind_speed',      'unit': 'km/h', 'state_class': 'measurement'},
        'AWINSP':     {'component': 'sensor', 'name': 'Average wind speed',  'device_class': 'wind_speed',      'unit': 'km/h', 'state_class': 'measurement'},
        'WINGS':      {'component': 'sensor', 'name': 'Wind gust',           'device_class': 'wind_speed',      'unit': 'km/h', 'state_class': 'measurement'},
        'WINDIR':     {'component': 'sensor', 'name': 'Wind direction',      'unit': '°',   'icon': 'mdi:compass', 'state_class': 'measurement'},

        # --- Power / energy ---
        'WATT':       {'component': 'sensor', 'name': 'Power',               'device_class': 'power',           'unit': 'W',   'state_class': 'measurement'},
        'KWATT':      {'component': 'sensor', 'name': 'Power',               'device_class': 'power',           'unit': 'kW',  'state_class': 'measurement'},
        'VOLT':       {'component': 'sensor', 'name': 'Voltage',             'device_class': 'voltage',         'unit': 'V',   'state_class': 'measurement'},
        'CURRENT':    {'component': 'sensor', 'name': 'Current',             'device_class': 'current',         'unit': 'A',   'state_class': 'measurement'},
        'CURRENT2':   {'component': 'sensor', 'name': 'Current phase 2',     'device_class': 'current',         'unit': 'A',   'state_class': 'measurement'},
        'CURRENT3':   {'component': 'sensor', 'name': 'Current phase 3',     'device_class': 'current',         'unit': 'A',   'state_class': 'measurement'},
        'METER':      {'component': 'sensor', 'name': 'Meter',               'state_class': 'total_increasing'},

        # --- Misc measurements ---
        'SOUND':      {'component': 'sensor', 'name': 'Sound',               'device_class': 'sound_pressure',  'unit': 'dB',  'state_class': 'measurement'},
        'DIST':       {'component': 'sensor', 'name': 'Distance',            'device_class': 'distance',        'unit': 'cm',  'state_class': 'measurement'},

        # --- Binary sensors ---
        'BAT':        {'component': 'binary_sensor', 'name': 'Battery',      'device_class': 'battery',         'payload_on': 'LOW', 'payload_off': 'OK'},
        'PIR':        {'component': 'binary_sensor', 'name': 'Motion',       'device_class': 'motion',          'payload_on': 'ON',  'payload_off': 'OFF'},
        'SMOKEALERT': {'component': 'binary_sensor', 'name': 'Smoke',        'device_class': 'smoke',           'payload_on': 'ON',  'payload_off': 'OFF'},

        # --- Controllable (read + write) ---
        'CMD':        {'component': 'switch', 'name': 'Switch',              'payload_on': 'ON',  'payload_off': 'OFF'},

        # --- Diagnostic / passthrough ---
        'SWITCH':     {'component': 'sensor', 'name': 'Switch id',           'entity_category': 'diagnostic'},
        'SET_LEVEL':  {'component': 'sensor', 'name': 'Dim level'},
        'CHIME':      {'component': 'sensor', 'name': 'Chime'},
    }

    def __init__(self, config) -> None:
        self.logger = logging.getLogger('RFLinkGW.HADiscovery')
        self.prefix = config['mqtt_prefix']
        self.data_format = config.get('mqtt_format', 'json')
        self.replace_spaces = config.get('mqtt_replace_spaces', False)
        self.discovery_prefix = config.get('ha_discovery_prefix', 'homeassistant')

    @staticmethod
    def _sanitize(value) -> str:
        """Home Assistant only allows [a-zA-Z0-9_-] in discovery topic components
        and object/unique ids."""
        return re.sub(r'[^a-zA-Z0-9_-]', '_', str(value))

    def _topic(self, raw_topic) -> str:
        """Build a data topic exactly the way MQTTClient.publish() does, so the
        discovery state/command topics match what is actually published."""
        topic = "%s/%s" % (self.prefix, raw_topic)
        if self.replace_spaces:
            topic = topic.replace(" ", "_")
        return topic

    def _switch_id(self, task):
        """For CMD entities the switch id is embedded in the read topic:
        family/deviceId/<switch>/READ/CMD -> <switch>."""
        parts = task['topic'].split('/')
        if len(parts) >= 5:
            return parts[2]
        return None

    def entity_key(self, task):
        """Stable key identifying one HA entity, used for de-duplication."""
        param = task['param'].upper()
        if param == 'CMD':
            return (task['family'], task['deviceId'], param, self._switch_id(task))
        return (task['family'], task['deviceId'], param)

    def build(self, task):
        """Return (config_topic, payload_dict) for a publish task, or None when
        no discovery config should be produced."""
        family = task['family']
        device_id = task['deviceId']
        param = task['param'].upper()

        spec = self.PARAM_MAP.get(param, {'component': 'sensor', 'name': param})
        component = spec['component']

        node_id = self._sanitize("rflink_%s_%s" % (family, device_id))
        switch_id = self._switch_id(task) if param == 'CMD' else None
        if switch_id is not None:
            object_id = self._sanitize("%s_cmd" % switch_id)
        else:
            object_id = self._sanitize(param)
        unique_id = "%s_%s" % (node_id, object_id)

        config_topic = "%s/%s/%s/%s/config" % (
            self.discovery_prefix, component, node_id, object_id
        )

        state_topic = self._topic(task['topic'])

        payload = {
            'name': spec.get('name', param),
            'unique_id': unique_id,
            'state_topic': state_topic,
            'device': {
                'identifiers': [node_id],
                'name': "%s %s" % (family, device_id),
                'manufacturer': 'RFLink',
                'model': family,
            },
        }

        # When publishing JSON payloads the value lives under "value".
        if self.data_format == 'json':
            payload['value_template'] = '{{ value_json.value }}'

        for key in ('device_class', 'state_class', 'entity_category', 'icon'):
            if key in spec:
                payload[key] = spec[key]
        if 'unit' in spec:
            payload['unit_of_measurement'] = spec['unit']

        if component == 'binary_sensor':
            payload['payload_on'] = spec['payload_on']
            payload['payload_off'] = spec['payload_off']

        if component == 'switch':
            # Read side: state_topic already set above.
            # Write side: family/deviceId/WRITE/<switch> (switch id is the RFLink
            # command "param", see SerialProcess.prepare_input).
            command_topic = self._topic(
                "%s/%s/WRITE/%s" % (family, device_id, switch_id)
            )
            payload['command_topic'] = command_topic
            payload['payload_on'] = spec['payload_on']
            payload['payload_off'] = spec['payload_off']
            payload['state_on'] = spec['payload_on']
            payload['state_off'] = spec['payload_off']

        return config_topic, payload
