import platform
import os
import subprocess
import ycm_core

DIR_OF_THIS_SCRIPT = os.path.abspath(os.path.dirname(__file__))
DIR_OF_THIRD_PARTY = os.path.join(DIR_OF_THIS_SCRIPT, 'third_party')
SOURCE_EXTENSIONS = ['.cpp', '.cxx', '.cc', '.c', '.m', '.mm']

# These are the compilation flags that will be used in case there's no
# compilation database set (by default, one is not set).
# CHANGE THIS LIST OF FLAGS. YES, THIS IS THE DROID YOU HAVE BEEN LOOKING FOR.
flags = [
    '-Wall',
    '-Wextra',
    '-Werror',
    '-Wno-long-long',
    '-Wno-variadic-macros',
    '-fexceptions',
    '-DNDEBUG',
    # You 100% do NOT need -DUSE_CLANG_COMPLETER and/or -DYCM_EXPORT in your flags;
    # only the YCM source code needs it.
    '-DUSE_CLANG_COMPLETER',
    '-DYCM_EXPORT=',
    # THIS IS IMPORTANT! Without the '-x' flag, Clang won't know which language to
    # use when compiling headers. So it will guess. Badly. So C++ headers will be
    # compiled as C headers. You don't want that so ALWAYS specify the '-x' flag.
    # For a C project, you would set this to 'c' instead of 'c++'.
    '-x',
    'c',
    '-isystem',
    '/usr/include',
    '-isystem',
    '/usr/local/include',
    '-Isrc',
    '-I3rd/libuv/include',
    '-I3rd/libsodium/src/libsodium/include',
]

# Clang automatically sets the '-std=' flag to 'c++14' for MSVC 2015 or later,
# which is required for compiling the standard library, and to 'c++11' for older
# versions.
if platform.system() != 'Windows':
    flags.append('-std=gnu99')


# Set this to the absolute path to the folder (NOT the file!) containing the
# compile_commands.json file to use that instead of 'flags'. See here for
# more details: http://clang.llvm.org/docs/JSONCompilationDatabase.html
#
# You can get CMake to generate this file for you by adding:
#   set( CMAKE_EXPORT_COMPILE_COMMANDS 1 )
# to your CMakeLists.txt file.
#
# Most projects will NOT need to set this to anything; you can just change the
# 'flags' list of compilation flags. Notice that YCM itself uses that approach.
compilation_database_folder = ''

if os.path.exists(compilation_database_folder):
    database = ycm_core.CompilationDatabase(compilation_database_folder)
else:
    database = None


def IsHeaderFile(filename):
    extension = os.path.splitext(filename)[1]
    return extension in ['.h', '.hxx', '.hpp', '.hh']


def FindCorrespondingSourceFile(filename):
    if IsHeaderFile(filename):
        basename = os.path.splitext(filename)[0]
        for extension in SOURCE_EXTENSIONS:
            replacement_file = basename + extension
            if os.path.exists(replacement_file):
                return replacement_file
    return filename


def Settings(**kwargs):
    if kwargs['language'] == 'cfamily':
        # If the file is a header, try to find the corresponding source file and
        # retrieve its flags from the compilation database if using one. This is
        # necessary since compilation databases don't have entries for header files.
        # In addition, use this source file as the translation unit. This makes it
        # possible to jump from a declaration in the header file to its definition
        # in the corresponding source file.
        filename = FindCorrespondingSourceFile(kwargs['filename'])

        if not database:
            return {
                'flags': flags,
                'include_paths_relative_to_dir': DIR_OF_THIS_SCRIPT,
                'override_filename': filename
            }

        compilation_info = database.GetCompilationInfoForFile(filename)
        if not compilation_info.compiler_flags_:
            return {}

        # Bear in mind that compilation_info.compiler_flags_ does NOT return a
        # python list, but a "list-like" StringVec object.
        final_flags = list(compilation_info.compiler_flags_)

        # NOTE: This is just for YouCompleteMe; it's highly likely that your project
        # does NOT need to remove the stdlib flag. DO NOT USE THIS IN YOUR
        # ycm_extra_conf IF YOU'RE NOT 100% SURE YOU NEED IT.
        try:
            final_flags.remove('-stdlib=libc++')
        except ValueError:
            pass

        return {
            'flags': final_flags,
            'include_paths_relative_to_dir': compilation_info.compiler_working_dir_,
            'override_filename': filename
        }

    return {}


def GetStandardLibraryIndexInSysPath(sys_path):
    for path in sys_path:
        if os.path.isfile(os.path.join(path, 'os.py')):
            return sys_path.index(path)
    raise RuntimeError('Could not find standard library path in Python path.')


def PythonSysPath(**kwargs):
    sys_path = kwargs['sys_path']
    for folder in os.listdir(DIR_OF_THIRD_PARTY):
        if folder == 'python-future':
            folder = os.path.join(folder, 'src')
            sys_path.insert(GetStandardLibraryIndexInSysPath(sys_path) + 1,
                            os.path.realpath(os.path.join(DIR_OF_THIRD_PARTY,
                                             folder)))
            continue

        if folder == 'cregex':
            interpreter_path = kwargs['interpreter_path']
            major_version = subprocess.check_output([interpreter_path, '-c', 'import sys; print(sys.version_info[0])']).rstrip().decode('utf8')
            folder = os.path.join(folder, 'regex_{}'.format(major_version))

        sys_path.insert(0, os.path.realpath(os.path.join(DIR_OF_THIRD_PARTY, folder)))
    return sys_path


def FlagsForFile(filename, **kwargs):
    return {'flags': flags}
