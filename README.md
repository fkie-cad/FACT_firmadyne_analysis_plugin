# FACT plug-in - Firmadyne
[![BCH compliance](https://bettercodehub.com/edge/badge/fkie-cad/FACT_firmadyne_analysis_plugin?branch=master)](https://bettercodehub.com/)  
:exclamation: **Caution:** This plug-in is quite experimental at the moment. Feel free to improve it.

[Firmadyne](https://github.com/firmadyne/firmadyne) integration into the [Firmware Analysis and Comparison Tool](https://fkie-cad.github.io/FACT_core/).

## Installation

Go to FACT's root directory and execute the following lines:

```sh
$ git submodule add https://github.com/fkie-cad/FACT_firmadyne_analysis_plugin.git src/plugins/analysis/firmadyne
$ ./install.py -B
``` 

If you add more than one additional plug-in, ```./install.py -B``` must be run just once after you added the last plug-in.
