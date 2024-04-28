## HWC routes uploader

See [the main script](routes-import.py) for more details.

Requires [Python 3](https://www.python.org/downloads/) and several additional
packages (see the `import` statements in the source code), which can be installed
with [pip](https://docs.python.org/3/installing/index.html)

See [post-data.md](post-data.md) for additional information.

## Example usage

Run the script in a command window. Use the `-h` option to see the command options

```console
david@blackbox:hwc$ ./routes-import.py -h
usage: routes-import.py [-h] [-n] [-v] username excel_file gpx_dir

positional arguments:
  username       HWC login username
  excel_file     Spreadsheet filename
  gpx_dir        Directory containing GPX files

options:
  -h, --help     show this help message and exit
  -n, --dry-run  Log in, check spreadsheet but don't upload anything
  -v, --verbose  Verbose output
david@blackbox:hwc$
```

To add routes to the HWC database, provide your username, spreadsheet and the
directory containing GPX files. The script will prompt for your password.

```console
david@blackbox:hwc$ ./routes-import.py your.hwc.login@example.com test/test.xlsx test/
Password: (enter your HWC web password here)
Created https://www.hobartwalkingclub.org.au/portal/routes/370/ from route 9319 DH test 1
david@blackbox:hwc$

```