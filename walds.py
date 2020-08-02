#!/usr/bin/env python

import os
import shlex
import shutil
from argparse import ArgumentParser

PROPER_HEADER_FIELD    = 'TT_TEAMLIST_TRAINING_5_CD'
SNOWFLAKE_HEADER_FIELD = 'TT_TEAMLIST_TRAINING_5_STEAM'
PROPER_TITLE_FIELD     = 'TRAINING_COMBO_ENTRIES_5_CD'
SNOWFLAKE_TITLE_FIELD  = 'TRAINING_COMBO_ENTRIES_5_STEAM'

LANGUAGE_FILE_ENCODING = 'UTF-8-SIG'
LANGUAGE_SUBDIRS_PATH = os.path.join('DATA', 'User', 'Languages')
LANGUAGE_DIRNAMES_RE = r'^[0-9.]*$'

WA_EXE_FILE = 'WA.exe'
VERSION_FIELD = b'FileVersion'
WA_REG_KEY_PATH = r'Software\Team17SoftwareLTD\WormsArmageddon'

BACKUP_FILE_SUFFIX = '.bak'

DEFAULT_INSTALL_PATHS = (
    r'C:\Program Files (x86)\Steam\steamapps\common\Worms Armageddon',
    r'C:\Program Files\Steam\steamapps\common\Worms Armageddon',
    r'C:\GOG Games\Worms Armageddon'
)


def get_install_folder(hist):
    """Tries to automatically find the W:A install directory. Tries registry if windows, then default folders.
       If automatic methods fail. Falls back to manual input request."""
    if os.name == 'nt':
        try:
            import winreg as reg
            with reg.OpenKey(reg.HKEY_CURRENT_USER, WA_REG_KEY_PATH, reserved=0, access=reg.KEY_QUERY_VALUE) as key:
                wa_path = reg.QueryValueEx(key, 'PATH')[0]
            return wa_path
        except Exception:
            pass

    for path in DEFAULT_INSTALL_PATHS:
        if os.path.isfile(os.path.join(path, WA_EXE_FILE)):
            return path

    if path := request_install_folder(hist):
        return path

    return False


def request_install_folder(hist):
    """Requests the user for the W:A install directory path and validates it. Tab completion and history is enabled on
       Linux. If an invalid path was specified when loading the program, then it is made available in the history."""
    if os.name == 'posix':
        import readline
        readline.set_completer_delims('\t\n=')
        if hist:
            readline.add_history(hist)
            print('Specified invalid install path added to history. Press up to edit it.\n')
        readline.parse_and_bind('tab: complete')
    print('Please enter the full path to your Worms Armageddon installation folder (or enter Q to quit).')
    print(f'Example: "{DEFAULT_INSTALL_PATHS[0]}"')
    while True:
        try:
            path = input('Enter path: ')
            path = os.path.expandvars(os.path.expanduser(path))
        except (KeyboardInterrupt, EOFError) as e:
            print(f'\nGot {e.__class__.__name__}. Quitting')
            exit(0)
        if path.upper() in ('Q', 'QUIT', 'EXIT', 'CANCEL'):
            print('OK. Quitting')
            exit(0)
        if os.path.isfile(os.path.join(path, WA_EXE_FILE)):
            return path
        print(f'ERROR: WA.exe file not found in: "{path}"')


def get_exe_version(exe_path):
    """Uses pefile to get the version string from the WA.exe file. Which should match the current language directory
       name in the language folder. Returns false if this is not possible. For example if pefile is not installed."""
    import pefile
    pe = pefile.PE(exe_path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

    if not hasattr(pe, 'VS_VERSIONINFO') or not hasattr(pe, 'FileInfo'):
        return False

    # FileInfo is now a list of lists since some PE files may have multiple VS_VERSION_INFO entries. Only parsing first.
    for entry in pe.FileInfo[0]:
        if hasattr(entry, 'StringTable'):
            for st_entry in entry.StringTable:
                if VERSION_FIELD in st_entry.entries:
                    return st_entry.entries[VERSION_FIELD].decode()
    return False


def get_lang_dir(install_path):
    """Gets the current language directory path. Tries pefile exe method first. Falls back to using the last directory
       in a sorted and filtered directory listing of the language folder."""
    lang_dirs_path = os.path.join(install_path, LANGUAGE_SUBDIRS_PATH)
    if not os.path.isdir(lang_dirs_path):
        return False

    exe_path = os.path.join(install_path, WA_EXE_FILE)
    try:
        if lang_dirname := get_exe_version(exe_path):
            return os.path.join(lang_dirs_path, lang_dirname)
    except Exception:
        pass

    import re
    regex = re.compile(LANGUAGE_DIRNAMES_RE)
    os.chdir(lang_dirs_path)
    if lang_dirnames := [d for d in os.listdir('.') if os.path.isdir(d) and regex.match(d)]:
        return os.path.join(lang_dirs_path, lang_dirnames[-1])

    return False


def restore_backups(lang_dir):
    """Replaces all files that have it with their corresponding backup file in a given language subfolder."""
    print('Restoring backed up files in:', lang_dir)
    os.chdir(lang_dir)

    file_paths = sorted([f for f in os.listdir('.') if f.lower().endswith('.bak')])
    if not file_paths:
        print('No backup files found.')
        return

    for file_path in file_paths:
        new_file_path = file_path[:-len(BACKUP_FILE_SUFFIX)]
        print('Restoring:', new_file_path)
        if os.path.isfile(new_file_path):
            os.remove(new_file_path)
        os.rename(file_path, new_file_path)


def fix_launguage_files(lang_dir, no_backup):
    """Replaces each steam entry with the corresponding cd entry for each file in a given language subfolder. While also
       trying to minimise any other changes such as inadvertent EOL or encoding conversions or changing whitespace."""
    print('Processing files in:', lang_dir)
    os.chdir(lang_dir)

    file_paths = sorted([f for f in os.listdir('.') if f.lower().endswith('.txt')])
    for file_path in file_paths:
        changes = False
        title, title_pos, title_line = ('', '', '')
        header, header_pos, header_line = ('', '', '')

        with open(file_path, mode='rt', encoding=LANGUAGE_FILE_ENCODING) as f:
            lines = f.read().splitlines()
            line_end = f.newlines

        for idx, line in enumerate(lines):
            stripped_line = line.strip().upper()
            if stripped_line.startswith('#'):
                continue

            if stripped_line.startswith(PROPER_HEADER_FIELD):
                header = shlex.split(line, posix=False)[-1]

            elif stripped_line.startswith(SNOWFLAKE_HEADER_FIELD):
                if '"' in line:
                    header_line = idx
                    header_pos = line.find('"')
                elif '"' in lines[idx + 1]:
                    header_line = idx + 1
                    header_pos = lines[idx + 1].find('"')

            elif stripped_line.startswith(PROPER_TITLE_FIELD):
                title = shlex.split(line, posix=False)[-1]

            elif stripped_line.startswith(SNOWFLAKE_TITLE_FIELD):
                if '"' in line:
                    title_line = idx
                    title_pos = line.find('"')
                elif '"' in lines[idx + 1]:
                    title_line = idx + 1
                    title_pos = lines[idx + 1].find('"')

        if header and header_pos and header_line:
            old = lines[header_line]
            new = old[:header_pos] + header
            if old != new:
                lines[header_line] = lines[header_line][:header_pos] + header
                changes = True

        if title and title_pos and title_line:
            old = lines[title_line]
            new = old[:title_pos] + title
            if old != new:
                lines[title_line] = lines[title_line][:title_pos] + title
                changes = True

        if changes:
            if not no_backup:
                shutil.copy2(file_path, file_path + BACKUP_FILE_SUFFIX)
            print('Desnowflaking:', file_path)
            with open(file_path, mode='wt', newline=line_end, encoding=LANGUAGE_FILE_ENCODING) as f:
                f.write('\n'.join(lines) + '\n')
        else:
            print('No fix needed:', file_path)


def main():
    """Use argparse to get the launch arguments and carry out the requested action. Validate manual input and fall back
       to automatic detection if it is invalid. Fail with error if language folder cannot be found."""
    parser = ArgumentParser(description='WALDS (Worms Armageddon Language file DeSnowflaker). An over-engineered tool'
                                        ' to correct silly political correctness pandering changes made to the Steam /'
                                        ' GoG language files of Worms Armageddon.')
    parser.add_argument('-p', '--wa-path', default=None, nargs='?', type=str,
                        help='The full Worms Armageddon installation folder path. Default is to autodetect.'
                             ' (Example: "{}")'.format(DEFAULT_INSTALL_PATHS[0]))
    parser.add_argument('-l', '--lang-dirname', default=None, nargs='?', type=str,
                        help='The language directory to work on. Named after current W:A version.'
                             ' Default is to autodetect latest. (Examples: 3.8 or 3.7.2.1)')
    parser.add_argument('--no-backup', action='store_true',
                        help='Disables the automatic backup of edited language files.')
    parser.add_argument('--restore', action='store_true',
                        help='Restores all modified language files from their backup file if available.')
    args = parser.parse_args()

    install_path = None
    if args.wa_path:
        install_path = os.path.expandvars(os.path.expanduser(args.wa_path))
        if not os.path.isdir(install_path):
            print('ERROR: Specified W:A install directory not found. Switching to auto detect dir.')
            args.wa_path = None
        elif not os.path.isfile(os.path.join(install_path, WA_EXE_FILE)):
            print(f'ERROR: Specified W:A install directory has no {WA_EXE_FILE} file. Switching to auto detect dir.')
            args.wa_path = None

    if not args.wa_path:
        install_path = get_install_folder(install_path)

    if args.lang_dirname:
        lang_dir_path = os.path.join(install_path, LANGUAGE_SUBDIRS_PATH, args.lang_dirname)
        if not os.path.isdir(lang_dir_path):
            print('ERROR: Specified language directory not found. Switching to auto detect.\n')
            args.lang_dirname = None
            lang_dir_path = None

    if not args.lang_dirname:
        lang_dir_path = get_lang_dir(install_path)

    if not lang_dir_path:
        parser.error('Could not resolve language directory. Is W:A installed properly?'
                     'Try manually specifying with --lang-dirname')

    if args.restore:
        restore_backups(lang_dir_path)
    else:
        fix_launguage_files(lang_dir_path, args.no_backup)
    

if __name__ == '__main__':
    main()
