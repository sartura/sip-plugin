# Sysrepo Sip plugin (DT)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**UCI**]() (Unified Configuration Interface) and Sysrepo/YANG datastore SIP configuration.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/sip-plugin

$ rm -rf build/* && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/sip-plugin/build

$ make && make install
[...]
[ 75%] Building C object CMakeFiles/sysrepo-plugin-dt-sip.dir/src/utils/memory.c.o
[100%] Linking C executable sysrepo-plugin-dt-sip
[100%] Built target sysrepo-plugin-dt-sip
[100%] Built target sysrepo-plugin-dt-sip
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-dt-sip
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-dt-sip" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/sip-plugin
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i terastream-sip@2017-08-09.yang
```

## YANG Overview

The `terastream-sip` YANG module with the `ts-sp` prefix consists of the following `container` paths:

* `/terastream-sip:asterisk` — container for Asterisk management,
* `/terastream-sip:sip` — configuration for SIP,
* `/terastream-sip:advanced` — configuration state data for the advanced SIP account,
* `/terastream-sip:digitmap` — contains direct dial numbers,

## Running and Examples

This plugin is installed as the `sysrepo-plugin-dt-sip` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-dt-sip
[INF]: Applying scheduled changes.
[INF]: No scheduled changes.
[INF]: Session 13 (user "jakov") created.
[INF]: plugin: start session to startup datastore
[INF]: Session 14 (user "jakov") created.
[INF]: plugin: subscribing to module change
[INF]: plugin: subscribing to get oper items
[INF]: plugin: plugin init done
```

Output from the plugin is expected; the plugin has loaded UCI configuration at `${SYSREPO_DIR}/etc/config/voice_client` into the `startup` datastore. We can confirm this by invoking the following commands:

```
$ cat ${SYSREPO_DIR}/etc/config/voice_client

config brcm_line 'brcm0'
	option extension '0000'
	option sip_account 'sip0'
	option noise '0'
	option vad '0'
	option txgain '0'
	option rxgain '0'
	option echo_cancel '1'
	option callwaiting '0'
	option clir '0'
	option name 'DECT 1'

config brcm_line 'brcm1'
	option extension '1111'
	option sip_account 'sip0'
	option noise '0'
	option vad '0'
	option txgain '0'
	option rxgain '0'
	option echo_cancel '1'
	option callwaiting '0'
	option clir '0'
	option name 'DECT 2'

config brcm_line 'brcm2'
	option extension '2222'
	option sip_account 'sip1'
	option noise '0'
	option vad '0'
	option txgain '0'
	option rxgain '0'
	option echo_cancel '1'
	option callwaiting '0'
	option clir '0'
	option name 'DECT 3'

config brcm_line 'brcm3'
	option extension '3333'
	option sip_account 'sip1'
	option noise '0'
	option vad '0'
	option txgain '0'
	option rxgain '0'
	option echo_cancel '1'
	option callwaiting '0'
	option clir '0'
	option name 'DECT 4'

config brcm_line 'brcm4'
	option extension '4444'
	option sip_account 'sip1'
	option noise '0'
	option vad '0'
	option txgain '0'
	option rxgain '0'
	option echo_cancel '1'
	option callwaiting '0'
	option clir '0'
	option name 'Tel 2'

config brcm_line 'brcm5'
	option extension '5555'
	option sip_account 'sip0'
	option noise '0'
	option vad '0'
	option txgain '0'
	option rxgain '0'
	option echo_cancel '1'
	option callwaiting '0'
	option clir '0'
	option name 'Tel 1'

config dialplan 'custom_dialplan'
	option custom_outgoing_enabled '1'
	option custom_incoming_enabled '1'
	option custom_hangup_enabled '1'
	option all_ports_extension '#123456'
	option test_audio_extension '#123457'
	option test_echo_extension '#123458'
	option record_message_extension '#999999'

config direct_dial 'direct_dial'
	list direct_dial '_112'
	list direct_dial '_116xxx'
	list direct_dial '_118xx'
	list direct_dial '_13xxx'
	list direct_dial '_19[2-5]'
	list direct_dial '_1987'
	list direct_dial '_[2-8]xxxxxx'
	list direct_dial '_0[2-5]x112'
	list direct_dial '_0[2-5]x[2-6]xxxxx'
	list direct_dial '_0[2-5]x7[0-79]xxxx'
	list direct_dial '_0[2-5]x8[0-8]xxxx'
	list direct_dial '_02x78xxxx[0-9T]'
	list direct_dial '_02x89xxxx'
	list direct_dial '_03178xxxx[0-9T]'
	list direct_dial '_03189xxxx'
	list direct_dial '_03[2-5]78xxxx'
	list direct_dial '_03[2-5]89xxxx[0-9T]'
	list direct_dial '_04[0348]78xxxx[0-9T]'
	list direct_dial '_04[0348]89xxxx'
	list direct_dial '_04[279]78xxxx'
	list direct_dial '_04[279]89xxxx[0-9T]'
	list direct_dial '_05x78xxxx'
	list direct_dial '_05x89xxxx[0-9T]'
	list direct_dial '_06[2459]xxxxxx'
	list direct_dial '_07[2467]xxxxxx'
	list direct_dial '_089xxxxxxxx'
	list direct_dial '_097[5679]xxxxxx'
	list direct_dial '_0980xxxxx'
	list direct_dial '_0981[36-9]xxxxx'
	list direct_dial '_098[2-8]xxxxx'
	list direct_dial '_0989xxxxxx'
	list direct_dial '_099[2-9]xxxxxx'
	list direct_dial '_x.[ET]'
	list direct_dial '_[*#]y.[#T]'

config sip_advanced 'SIP'
	option rtpstart '10000'
	option rtpend '20000'
	option dtmfmode 'rfc2833'
	option remotehold 'yes'
	option contact_line_suffix '1'
	option registertimeoutbackoff '512'
	option registerattemptsbackoff '0'
	option register403timeout '0'
	option register503timeout '0'
	option registertimeoutguardsecs '15'
	option registertimeoutguardlimit '30'
	option registertimeoutguardpct '0.2'
	option defaultexpiry '300'
	option tls_version 'tlsv1'
	option tls_cipher 'DES-CBC3-SHA'
	option dnsmgr 'no'
	option dnsmgr_refresh_interval '300'
	option srvlookup 'yes'
	option bindintf 'wan'

config brcm_advanced 'BRCM'
	option country 'USA'
	option jbenable 'yes'
	option jbforce 'no'
	option jbmaxsize '500'
	option jbimpl 'adaptive'
	option genericplc 'yes'
	option dialoutmsec '4000'
	option cw_enable 'yes'

config features 'features'
	option cbbs_enabled '1'
	option callforward_enabled '1'
	option redial_enabled '1'
	option callreturn_enabled '1'
	option advanced_register_settings '1'

config log 'LOG'
	option console 'notice,warning,error'
	option messages 'error'
	option syslog_facility 'local0'

config ringing_status 'RINGING_STATUS'
	option status '0'
	option enabled '0'
	option shouldring '1'

config call_filter 'call_filter0'
	option block_foreign '0'
	option block_special_rate '0'
	option block_outgoing '0'
	option block_incoming '0'

config cdr_log 'CDR_LOG'
	option cdr_syslog '0'

config sip_service_provider 'sip0'
	option autoframing '1'
	option cfim_on '*21*'
	option cfim_off '#21#'
	option cfbs_on '*61*'
	option cfbs_off '#61#'
	option call_return '*69'
	option redial '*66'
	option is_fax '0'
	option transport 'udp'
	option enabled '1'
	option name 'PANTERA-1'
	option host 'ims.t-com.hr'
	option displayname '+3852140873X'
	option user '+3852140873X'
	option authuser '3852140873X'
	option domain 'ims.t-com.hr'
	option codec0 'alaw'
	option codec1 'ulaw'
	option codec2 'g729'
	option call_lines 'BRCM/5'

config sip_service_provider 'sip1'
	option autoframing '1'
	option cfim_on '*21*'
	option cfim_off '#21#'
	option cfbs_on '*61*'
	option cfbs_off '#61#'
	option call_return '*69'
	option redial '*66'
	option is_fax '0'
	option transport 'udp'
	option enabled '1'
	option name 'PANTERA-2'
	option host 'ims.t-com.hr'
	option displayname '+3852140873X'
	option user '+3852140873X'
	option authuser '3852140873X'
	option domain 'ims.t-com.hr'
	option codec0 'alaw'
	option codec1 'ulaw'
	option codec2 'g729'
	option call_lines 'BRCM/4'


$ sysrepocfg -X -d startup -f json -m 'terastream-sip'
{
  "terastream-sip:sip": {
    "advanced": {
      "rtpstart": "10000",
      "rtpend": "20000",
      "dtmfmode": "rfc2833"
    },
    "sip-account": [
      {
        "account": "brcm0",
        "account_name": "DECT 1"
      },
      {
        "account": "brcm1",
        "account_name": "DECT 2"
      },
      {
        "account": "brcm2",
        "account_name": "DECT 3"
      },
      {
        "account": "brcm3",
        "account_name": "DECT 4"
      },
      {
        "account": "brcm4",
        "account_name": "Tel 2"
      },
      {
        "account": "brcm5",
        "account_name": "Tel 1"
      }
    ]
  }
}
```

Provided output suggests that the plugin has correctly initialized Sysrepo `startup` datastore with appropriate data transformations.

Changes to the `running` datastore can be done manually by invoking the following command:

```
$ sysrepocfg -E -d running -f json -m 'terastream-sip'
[...interactive...]
{
  "terastream-sip:sip": {
    "advanced": {
      "rtpstart": "10000",
      "rtpend": "20000",
      "dtmfmode": "rfc2833"
    },
    "sip-account": [
      {
        "account": "brcm0",
        "account_name": "DECT 1"
      },
      {
        "account": "brcm1",
        "account_name": "DECT 2"
      },
      {
        "account": "brcm2",
        "account_name": "DECT 3"
      },
      {
        "account": "brcm3",
        "account_name": "DECT 4"
      },
      {
        "account": "brcm4",
        "account_name": "Tel 2"
      },
      {
        "account": "brcm5",
        "account_name": "Tel 1"
      }
    ]
  }
}
```

Alternatively, instead of changing the entire module data with `-m 'terastream-sip'` we can change data on a certain XPath with e.g. `-x '/terastream-sip:sip-account'`.


In constrast to the configuration state data, using `sysrepocfg` we can access `operational` state data. For example:

```
$ 'sysrepocfg -X -d operational -f json -x '/terastream-sip:sip/sip-account'
{
  "terastream-sip:sip": {
    "sip-account": [
      {
        "account": "brcm0",
        "account_name": "DECT 1"
      },
      {
        "account": "brcm1",
        "account_name": "DECT 2"
      },
      {
        "account": "brcm2",
        "account_name": "DECT 3"
      },
      {
        "account": "brcm3",
        "account_name": "DECT 4"
      },
      {
        "account": "brcm4",
        "account_name": "Tel 2"
      },
      {
        "account": "brcm5",
        "account_name": "Tel 1"
      }
    ]
  }
}
```