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
import sys
import argparse
import re
import requests
import pandas
import json
import html
import time
import glob
import gpxpy
from getpass import getpass
from pathlib import Path

login_url = 'https://www.hobartwalkingclub.org.au/account/login/?next=/portal/'
landing_page = 'https://www.hobartwalkingclub.org.au/portal/'

form_urls = dict(walk='https://www.hobartwalkingclub.org.au/portal/routes/walk/add',
                 cycle='https://www.hobartwalkingclub.org.au/portal/routes/cycle/add')

throttle = 1 # Seconds between requests to avoid triggering any HTTP rate limiting

regions = (
    "North West Tasmania",
    "North East Tasmania",
    "Western Tasmania",
    "Cradle - Lake St Clair",
    "Central Plateau",
    "Midlands",
    "Upper Gordon",
    "Southern Tasmania",
    "South East Tasmania",
    "kunanyi / Mt Wellington"
)

grades = (
    "", "SNQ", "NQ", "SE", "SM", "SR", "ME", "MM", "MR", "LM", "LR", "S", "M", "L"
)

gpx_management = {
    'gpx_uploads-INITIAL_FORMS': 0,
    'gpx_uploads-MIN_NUM_FORMS': 0,
    'gpx_uploads-MAX_NUM_FORMS': 1000,
    'gpx_uploads-TOTAL_FORMS': 0
}

def warn_sus_text(label, text):
    if re.search(r'<[a-zA-Z][^<>]*>', text):
        print(f"{label}: May be HTML", file=sys.stderr)

def text_to_quill(text):
    # See https://quilljs.com/docs/delta/ https://github.com/leehanyeong/django-quill-editor
    lines = re.sub('\n+', '\n', text.strip('\n'))
    clean_html = '\n'.join([f'<p>{html.escape(ln)}</p>'
                           for ln in lines.split('\n')])
    return json.dumps(dict(
        delta=json.dumps(dict(ops=[{'insert':lines + '\n'}])),
        html=clean_html))

def split_time(hms_string):
    if not hms_string:
        return '', ''
    if ':' in hms_string:
        # Parse duration like '4:00:00
        hms = hms_string.split(':')
        # Minutes have to be a multiple of 15
        m = round((int(hms[0]) * 60 + int(hms[1])) / 15) * 15
    else:
        # assume decimal
        m = round((60 * float(hms_string)) / 15) * 15
    return str(m // 60), str(m % 60)

def extract_csrf_token(html_str):
    return re.search(
        r'<input\s+type="hidden"\s+name="csrfmiddlewaretoken"\s+value="([^"]+)"\s*>',
        html_str).group(1)

def check(ok, message=None):
    if not ok: raise RuntimeError(message)

def to_int(v):
    return v and str(round(float(v)))

class Uploader:
    session = None

    def __init__(self, args, password, header):
        self.args = args
        self.session = requests.Session()
        r = self.session.get(login_url)
        check(r.status_code == 200, f'Login page inaccessible ({r.status_code})')
        if password:
            data = dict(csrfmiddlewaretoken=extract_csrf_token(r.text),
                        login=args.username, password=password)
            time.sleep(throttle)
            r = self.session.post(login_url, data=data, headers={'referer': login_url})
            check(r.status_code == 200, f'Login failed ({r.status_code})')
            check(r.url == landing_page, f'Login failed (redirected to {r.url})')
        # Sanitise column labels to xxxx or xxxx_yyyy
        self.header = ['_'.join(h.lower().strip().split()[:2])
                       for h in header]
        self.errors = []

    def check_call(self, func, message, *args, fail_val=None,):
        try:
            return func(*args)
        except (RuntimeError, IndexError, ValueError, TypeError) as e:
            self.errors.append(f"{message}: {', '.join(args)}")
            return fail_val

    def find_gpx(self, original_id):
        return glob.glob(
            f'{original_id}.gpx', root_dir=self.args.gpx_dir) + glob.glob(
            f'{original_id}[_ -]*.gpx', root_dir=self.args.gpx_dir)

    def process_row(self, row):
        row_dict = dict(
            zip(self.header,
                (('' if pandas.isna(c) else str(c).strip())
                 for c in row)))
        url = form_urls[row_dict.get('route_type', 'walk')]

        data = {}
        self.errors = []
        try:
            original_id = row_dict['route_no']
            title = row_dict['route_name']
            if len(title) > 30:
                self.errors.append("Route name is too long")
            self.check_call(int, "Bad route no.", original_id)
            self.check_call(regions.index, "Bad region", row_dict['region'])
            self.check_call(grades.index, "Bad grade", row_dict['grade'])
            h_m = self.check_call(split_time, "Bad time", row_dict['duration'],
                                  fail_val=(None, None))
            for k in ('distance', 'height_gain', 'drive_distance'):
                self.check_call(lambda v: v and float(v),
                                f"Bad {k}", row_dict[k])

            for k in 'location', 'description':
                warn_sus_text(f"Route {original_id} {k}", row_dict[k])
            location = text_to_quill(row_dict['location'])
            route_details = text_to_quill(row_dict['description'])
            if self.errors:
                print(f"Route no {original_id}: {'. '.join(self.errors)}",
                      file=sys.stderr)
                return
            gps_plot = row_dict['gps_plot']
            data['title'] = title
            data['region'] = row_dict['region']
            data['grade'] = row_dict['grade']
            data['distance_km'] = row_dict['distance']
            data['height'] = to_int(row_dict['height_gain'])
            data['peak_altitude'] = ''
            data['duration_0'], data['duration_1'] = h_m
            data['private_land'] = 'on' if row_dict['land_owner'] else ''
            data['land_owner'] = row_dict['land_owner']
            data['start_location'] = row_dict['start']
            data['end_location'] = ''
            data['car_shuttle'] = ''
            data['driving_distance_km'] = to_int(row_dict['drive_distance'])
            data['trailhead'] = ''
            data['track'] = ''
            data['route_info'] = row_dict['author']
            data['last_updated'] = ''
            data['maps'] = row_dict['map_details']
            data['nomenclature'] = text_to_quill('')
            data['location'] = location
            data['route_details'] = route_details
            data['original_id'] = original_id
            data['status'] = 'Not Reviewed'
        except KeyError as e:
            raise RuntimeError(f"Missing column in {self.args.excel_file}: {e}")

        data.update(gpx_management)
        files = {}
        timestamp = None

        matches = self.find_gpx(original_id)
        if not matches:
            # Handle things like "yes  see 1472"
            for other_route in re.findall(r'[1-9][0-9]*', gps_plot):
                matches += self.find_gpx(other_route)

        for i, gpx_filename in enumerate(matches):
            gpx_path = Path(self.args.gpx_dir) / gpx_filename
            files[f'gpx_uploads-{i}-gpx_file'] = (
                gpx_filename, gpx_path.open(), 'application/gpx+xml')
            data[f'gpx_uploads-{i}-id'] = ''
            data[f'gpx_uploads-{i}-route'] = ''
            try:
                gpx = gpxpy.parse(gpx_path.open())
            except gpxpy.gpx.GPXException as e:
                print(f"Bad GPX file {gpx_path}: {e}", file=sys.stderr)
                return
            all_timestamps = [seg.points[0].time
                    for trk in gpx.tracks
                    for seg in trk.segments] + [timestamp]
            timestamp = min((t for t in all_timestamps if t),
                            default=None)

        if timestamp:
            data['last_updated'] = timestamp.astimezone().strftime('%Y-%m-%d')
        data['gpx_uploads-TOTAL_FORMS'] = len(matches)

        if self.args.verbose:
            print('')
            for o in data, files:
                for k, v in o.items():
                    print(k, ':', v)

        if self.args.dry_run:
            print(f"Route {original_id} {title} {matches} {data['last_updated']}")
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
            print(f'Created {r.url} from route {original_id} {title} {matches} {data["last_updated"]}')
        else:
            print(f'Upload failed ({original_id} {data["title"]}, {r.url})',
                  file=sys.stderr)
            # Form validation errors are reported like
            # <ul class="errorlist"><li>Select a valid choice. xxx is not one of the available choices.</li></ul>
            for err in re.findall(r'(<ul\b[^>]+?\berrorlist\b.*?</ul>)', r.text):
                print(err, file=sys.stderr)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Log in, check spreadsheet but don't upload anything")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-s", "--start", action="store", type=int,
                        help="Start row (first row is 1)", default=1)
    parser.add_argument("-e", "--end", action="store", type=int,
                        help="Last row", default=None)
    parser.add_argument("username", help="HWC login username")
    parser.add_argument("excel_file", help="Spreadsheet filename")
    parser.add_argument("gpx_dir", help="Directory containing GPX files")
    args = parser.parse_args()

    routes = pandas.read_excel(args.excel_file)
    header = routes.columns.tolist()

    password = None if args.dry_run else getpass()
    u = Uploader(args, password, header)
    for _, row in routes[args.start-1:args.end].iterrows():
        u.process_row(row)

if __name__ == "__main__":
    main()
