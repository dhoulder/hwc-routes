#!/usr/bin/env python3
"""
Import routes in an excel spreadsheet into the Hobart Walking Club routes
database.

The most efficient way to do this would ordinarily be to do this server-side,
using the Django loaddata command. However, the HWC web app is maintained by a
commercial entity and this was going to be cost prohibitive.

Instead, we do it client-side and use the requests module to POST the data into
the route-creation form as a human would.
"""
import argparse
import re
import requests
import pandas
import bleach
import json
import html
import time

from getpass import getpass
from pathlib import Path

login_url = 'https://www.hobartwalkingclub.org.au/account/login/?next=/portal/'
landing_page = 'https://www.hobartwalkingclub.org.au/portal/'

form_urls = dict(walk='https://www.hobartwalkingclub.org.au/portal/routes/walk/add',
                 cycle='https://www.hobartwalkingclub.org.au/portal/routes/cycle/add')

throttle = 1 # Seconds between requests to avoid triggering any HTTP rate limiting

fields = (
    'title',
    'region',
    'grade',
    'distance_km',
    'height',
    'peak_altitude',
    # 'duration', # Needs to be split into  duration_0, duration_1.
    # 'private_land', #  Translate 1 to "on", otherwise blank
    'land_owner',
    'start_location',
    'end_location',
    # 'car_shuttle', #  Translate 1, 0 to "on", otherwise blank
    'driving_distance_km',
    #'trailhead',  # Needs to be like POINT (147.30860923899715 -42.86577574650763)
    'track',
    'route_info',
    'last_updated',
    'maps',
    # 'nomenclature', # See html_to_quill()
    # 'location',
    #'route_details'
    )

regions = (
    "North West Tasmania",
    "North East Tasmania",
    "Western Tasmania",
    "Cradle - Lake St Clair",
    "Central Plateau",
    "Upper Gordon",
    "Southern Tasmania",
    "South East Tasmania",
    "kunanyi / Mt Wellington"
)

gpx_management = {
    'gpx_uploads-INITIAL_FORMS': 0,
    'gpx_uploads-MIN_NUM_FORMS': 0,
    'gpx_uploads-MAX_NUM_FORMS': 1000,
    'gpx_uploads-TOTAL_FORMS': 0
}

def html_to_quill(html_str):
    # See https://quilljs.com/docs/delta/ https://github.com/leehanyeong/django-quill-editor
    clean_html = bleach.clean(html_str, tags={'p'}, attributes=[], strip=True)
    lines = html.unescape(
        re.sub('\n+', '\n',
               re.sub(r'</?p *>', '\n',
                      clean_html.replace('\n', ' ')).lstrip('\n') + '\n'))
    return json.dumps(dict(
        delta=json.dumps(dict(ops=[{'insert':lines}])),
        html=clean_html))

def split_time(hms_string):
    # Parse duration like '4:00:00
    if not hms_string:
        return '', ''
    hms = hms_string.split(':')
    # Minutes have to be a multiple of 15
    m = round((int(hms[0]) * 60 + int(hms[1])) / 15) * 15
    return str(m // 60), str(m % 60)

def clean_point(point_string):
    # Translate from SRID=4326;POINT (146.62542930877686 -42.676847280577576) to
    # POINT (146.62542930877686 -42.676847280577576)
    return point_string and re.search(
        r'(\bPOINT\b.*)', point_string, flags=re.IGNORECASE).group(1)

def flag_to_on(v):
    return 'on' if v not in {'', '0'} else ''

def extract_csrf_token(html_str):
    return re.search(
        r'<input\s+type="hidden"\s+name="csrfmiddlewaretoken"\s+value="([^"]+)"\s*>',
        html_str).group(1)

def check(ok, message):
    if not ok: raise RuntimeError(message)

class Uploader:
    session = None

    def __init__(self, args, password, header):
        self.args = args
        self.session = requests.Session()
        r = self.session.get(login_url)
        check(r.status_code == 200, f'Login page inaccessible ({r.status_code})')
        data = dict(csrfmiddlewaretoken	= extract_csrf_token(r.text),
                    login=args.username, password=password)
        time.sleep(throttle)
        r = self.session.post(login_url, data=data, headers={'referer': login_url})
        check(r.status_code == 200, f'Login failed ({r.status_code})')
        check(r.url == landing_page, f'Login failed (redirected to {r.url})')
        self.header = header

    def process_row(self, row):
        row_dict = dict(zip(self.header,
                            (('' if pandas.isna(c) else str(c).strip()) for c in row)))
        original_id = row_dict['id']
        url = form_urls[row_dict.get('route_type', 'walk')]

        data = {k: row_dict[k] for k in fields}
        data['duration_0'], data['duration_1'] = split_time(row_dict['duration'])
        data['car_shuttle'] = flag_to_on(row_dict['car_shuttle'])
        data['private_land'] = flag_to_on(row_dict['private_land'])
        data['trailhead'] = clean_point(row_dict['trailhead'])
        data['nomenclature'] = html_to_quill(row_dict['nomenclature'])
        data['location'] = html_to_quill(row_dict['location'])
        data['route_details'] = html_to_quill(row_dict['route_details'])

        check(data['region'] in regions,
              f"Bad region: {data['region']}  ({original_id} {data['title']})")
        lu = data['last_updated'].split('-') # Needs to be like 2024-04-10
        if lu:
            check(len(lu) == 3
                  and int(lu[0]) > 1900 and (0 < int(lu[1]) < 13) and int(lu[2]) < 32,
                  f'Bad date format {data["last_updated"]} ({original_id} {data["title"]})')

        data.update(gpx_management)
        files = {}
        gpx_filename = f'{original_id}.gpx'
        gpx_path = Path(self.args.gpx_dir) / gpx_filename
        if gpx_path.is_file():
            files = {'gpx_uploads-0-gpx_file':
                    (gpx_filename, gpx_path.open(), 'application/gpx+xml')}
            data['gpx_uploads-TOTAL_FORMS'] = 1
            data['gpx_uploads-0-id'] = ''
            data['gpx_uploads-0-route'] = ''

        if self.args.verbose:
            print('')
            for o in data, files:
                for k, v in o.items():
                    print(k, ':', v)

        if self.args.dry_run:
            return

        time.sleep(throttle)
        r = self.session.get(url)
        check(r.status_code == 200, f'Failed to fetch {url} ({r.status_code})')
        check(r.url == url, f'{url} redirected to ({r.url})')
        data['csrfmiddlewaretoken'] = extract_csrf_token(r.text)

        time.sleep(throttle)
        r = self.session.post(url, data=data, files=files, headers={'referer': url})
        check(r.status_code == 200,
              f'Upload failed ({original_id} {data["title"]}, {r.status_code})')
        if re.search('/portal/routes/[0-9]+/$', r.url):
            print(f'Created {r.url} from route {original_id} {data["title"]}')
        else:
            print(f'Upload failed ({original_id} {data["title"]}, {r.url})')
            # Form validation errors are reported like
            # <ul class="errorlist"><li>Select a valid choice. xxx is not one of the available choices.</li></ul>
            for err in re.findall(r'(<ul\b[^>]+?\berrorlist\b.*?</ul>)', r.text):
                print(err)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Log in, check spreadsheet but don't upload anything")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("username", help="HWC login username")
    parser.add_argument("excel_file", help="Spreadsheet filename")
    parser.add_argument("gpx_dir", help="Directory containing GPX files")
    args = parser.parse_args()

    routes = pandas.read_excel(args.excel_file)
    header = routes.columns.tolist()

    password = getpass()
    u = Uploader(args, password, header)
    for index, row in routes.iterrows():
        u.process_row(row)

if __name__ == "__main__":
    main()
