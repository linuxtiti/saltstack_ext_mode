# -*- coding: utf-8 -*-
"""
This is a EXECUTION MODULE
using pexpect to switch another user
excute os command and script(.sh,.py,etc),and the script must be on the minion
windows is not supported

"""

#import Python libs
import os,subprocess,logging,traceback,shutil
from os.path import basename

#import Salt libs
import salt.utils
import salt.utils.timed_subprocess
import salt.grains.extra
import salt.ext.six as six
from salt.utils import vt
from salt.exceptions import CommandExecutionError, TimedProcTimeoutError
from salt.log import LOG_LEVELS

__virtualname__ = "su_cmd"
su_cmd_version = "0.22-dev"
DEFAULT_SHELL = salt.grains.extra.shell()['shell']
log = logging.getLogger(__name__)

try:
    import pexpect
    HAS_LIBS = True
except ImportError:
    log.debug('can not import pexpect module')
    HAS_LIBS = False


# Only available on POSIX systems, nonfatal on windows
try:
    import pwd
except ImportError:
    pass


if salt.utils.is_windows():
    from salt.utils.win_runas import runas as win_runas
    HAS_WIN_RUNAS = True
else:
    HAS_WIN_RUNAS = False


def __virtual__():
    '''
    Overwriting the cmd python module makes debugging modules
    with pdb a bit harder so lets do it this way instead.
    '''
    if HAS_LIBS:
        return __virtualname__
    else:
        return False


def display_ver():
    module_name = __name__
    info_ret = {
        "name": module_name,
        "version": su_cmd_version
    }
    return info_ret


def _check_cb(cb_):
    '''
    If the callback is None or is not callable, return a lambda that returns
    the value passed.
    '''
    if cb_ is not None:
        if hasattr(cb_, '__call__'):
            return cb_
        else:
            log.error('log_callback is not callable, ignoring')
    return lambda x: x


def _is_valid_shell(shell):
    '''
    Attempts to search for valid shells on a system and
    see if a given shell is in the list
    '''
    if salt.utils.is_windows():
        return True  # Don't even try this for Windows
    shells = '/etc/shells'
    available_shells = []
    available_shell_names = []
    if os.path.exists(shells):
        try:
            with salt.utils.fopen(shells, 'r') as shell_fp:
                lines = shell_fp.read().splitlines()
            for line in lines:
                if line.startswith('#'):
                    continue
                else:
                    available_shells.append(line)
                    available_shell_names.append(basename(line))
        except OSError:
            return True
    else:
        # No known method of determining available shells
        return None
    if shell in available_shells or shell in available_shell_names:
        return True
    else:
        return False


def _python_shell_default(python_shell, __pub_jid):
    '''
    Set python_shell default based on remote execution and __opts__['cmd_safe']
    '''
    try:
        # Default to python_shell=True when run directly from remote execution
        # system. Cross-module calls won't have a jid.
        if __pub_jid and python_shell is None:
            return True
        elif __opts__.get('cmd_safe', True) is False and python_shell is None:
            # Override-switch for python_shell
            return True
    except NameError:
        pass
    return python_shell


def _render_cmd(cmd, cwd, template, saltenv='base', pillarenv=None, pillar_override=None):
    '''
    If template is a valid template engine, process the cmd and cwd through
    that engine.
    '''
    if not template:
        return (cmd, cwd)

    # render the path as a template using path_template_engine as the engine
    if template not in salt.utils.templates.TEMPLATE_REGISTRY:
        raise CommandExecutionError(
            'Attempted to render file paths with unavailable engine '
            '{0}'.format(template)
        )

    kwargs = {}
    kwargs['salt'] = __salt__
    if pillarenv is not None or pillar_override is not None:
        pillarenv = pillarenv or __opts__['pillarenv']
        kwargs['pillar'] = _gather_pillar(pillarenv, pillar_override)
    else:
        kwargs['pillar'] = __pillar__
    kwargs['grains'] = __grains__
    kwargs['opts'] = __opts__
    kwargs['saltenv'] = saltenv

    def _render(contents):
        # write out path to temp file
        tmp_path_fn = salt.utils.mkstemp()
        with salt.utils.fopen(tmp_path_fn, 'w+') as fp_:
            fp_.write(contents)
        data = salt.utils.templates.TEMPLATE_REGISTRY[template](
            tmp_path_fn,
            to_str=True,
            **kwargs
        )
        salt.utils.safe_rm(tmp_path_fn)
        if not data['result']:
            # Failed to render the template
            raise CommandExecutionError(
                'Failed to execute cmd with error: {0}'.format(
                    data['data']
                )
            )
        else:
            return data['data']

    cmd = _render(cmd)
    cwd = _render(cwd)
    return (cmd, cwd)


def _check_loglevel(level='info', quiet=False):
    '''
    Retrieve the level code for use in logging.Logger.log().
    '''
    def _bad_level(level):
        log.error(
            'Invalid output_loglevel \'{0}\'. Valid levels are: {1}. Falling '
            'back to \'info\'.'
            .format(
                level,
                ', '.join(
                    sorted(LOG_LEVELS, key=LOG_LEVELS.get, reverse=True)
                )
            )
        )
        return LOG_LEVELS['info']

    if salt.utils.is_true(quiet) or str(level).lower() == 'quiet':
        return None

    try:
        level = level.lower()
        if level not in LOG_LEVELS:
            return _bad_level(level)
    except AttributeError:
        return _bad_level(level)

    return LOG_LEVELS[level]


def _parse_env(env):
    if not env:
        env = {}
    if isinstance(env, list):
        env = salt.utils.repack_dictlist(env)
    if not isinstance(env, dict):
        env = {}
    return env


def _gather_pillar(pillarenv, pillar_override):
    '''
    Whenever a state run starts, gather the pillar data fresh
    '''
    pillar = salt.pillar.get_pillar(
        __opts__,
        __grains__,
        __opts__['id'],
        __opts__['environment'],
        pillar=pillar_override,
        pillarenv=pillarenv
    )
    ret = pillar.compile_pillar()
    if pillar_override and isinstance(pillar_override, dict):
        ret.update(pillar_override)
    return ret


def _check_avail(cmd):
    '''
    Check to see if the given command can be run
    '''
    bret = True
    wret = False
    if __salt__['config.get']('cmd_blacklist_glob'):
        blist = __salt__['config.get']('cmd_blacklist_glob', [])
        for comp in blist:
            if fnmatch.fnmatch(cmd, comp):
                # BAD! you are blacklisted
                bret = False
    if __salt__['config.get']('cmd_whitelist_glob', []):
        blist = __salt__['config.get']('cmd_whitelist_glob', [])
        for comp in blist:
            if fnmatch.fnmatch(cmd, comp):
                # GOOD! You are whitelisted
                wret = True
                break
    else:
        # If no whitelist set then alls good!
        wret = True
    return bret and wret


def _su_run(cmd,
         cwd=None,
         stdin=None,
         stdout=subprocess.PIPE,
         stderr=subprocess.PIPE,
         output_loglevel='debug',
         log_callback=None,
         runas=None,
         su_user=None,
         su_method="su",
         password=None,
         shell=DEFAULT_SHELL,
         python_shell=False,
         env=None,
         clean_env=False,
         rstrip=True,
         template=None,
         umask=None,
         timeout=None,
         with_communicate=True,
         reset_system_locale=True,
         ignore_retcode=False,
         saltenv='base',
         pillarenv=None,
         pillar_override=None,
         use_vt=False,
         bg=False,
         encoded_cmd=False,
         **kwargs):
    '''
    Do the DRY thing and only call subprocess.Popen() once
    '''
    """
    set runas None,no matter what's input
    """
    runas = None
    shell_fullpath = None

    if 'pillar' in kwargs and not pillar_override:
        pillar_override = kwargs['pillar']
    if _is_valid_shell(shell) is False:
        log.warning(
            'Attempt to run a shell command with what may be an invalid shell! '
            'Check to ensure that the shell <{0}> is valid for this user.'
            .format(shell))

    log_callback = _check_cb(log_callback)

    # Set the default working directory to the home directory of the user
    # salt-minion is running as. Defaults to home directory of user under which
    # the minion is running.
    if not cwd:
        cwd = os.path.expanduser('~{0}'.format('' if not runas else runas))

        # make sure we can access the cwd
        # when run from sudo or another environment where the euid is
        # changed ~ will expand to the home of the original uid and
        # the euid might not have access to it. See issue #1844
        if not os.access(cwd, os.R_OK):
            cwd = '/'
            if salt.utils.is_windows():
                cwd = os.tempnam()[:3]
    else:
        # Handle edge cases where numeric/other input is entered, and would be
        # yaml-ified into non-string types
        cwd = str(cwd)

    if not salt.utils.is_windows():
        if not os.path.isfile(shell) or not os.access(shell, os.X_OK):
            msg = 'The shell {0} is not available,maybe it is not a fullpath'.format(shell)
            #raise CommandExecutionError(msg)
            #ret = {"stdout":None,"stderr":msg,"retcode":"1","pid":None}
            #return ret
            log.debug(msg)
            log.debug('we will try to find the shell: \'{0}\' in sys path'.format(shell))
            shell = basename(shell)
            cmd_str = "which " + shell
            p = subprocess.Popen(cmd_str, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            cmd_ret_code = p.wait()
            if cmd_ret_code == 0:
                shell_fullpath = p.stdout.readline().strip()
                log.debug('found a match shell \'{0}\' on minion'.format(shell_fullpath))
            else:
                shell_fullpath = DEFAULT_SHELL
                log.debug('Warning: can not find the shell excutor you ask for,use system default \'{0}\' instead'.format(shell_fullpath))
                
            
    if salt.utils.is_windows() and use_vt:  # Memozation so not much overhead
        #raise CommandExecutionError('VT not available on windows')
        msg = 'VT not available on windows'
        ret = {"stdout":None,"stderr":msg,"retcode":"1","pid":None}
        return ret

    if shell.lower().strip() == 'powershell':
        ret = {"stdout":None,"stderr":"not supported powershell right now","retcode":"1","pid":None}
        return ret
        """
        stack = traceback.extract_stack(limit=2)
        if stack[-2][2] == 'script':
            cmd = 'Powershell -NonInteractive -ExecutionPolicy Bypass -File ' + cmd
        elif encoded_cmd:
            cmd = 'Powershell -NonInteractive -EncodedCommand {0}'.format(cmd)
        else:
            cmd = 'Powershell -NonInteractive "{0}"'.format(cmd.replace('"', '\\"'))
        """

    # munge the cmd and cwd through the template
    (cmd, cwd) = _render_cmd(cmd, cwd, template, saltenv, pillarenv, pillar_override)

    ret = {}

    # If the pub jid is here then this is a remote ex or salt call command and needs to be
    # checked if blacklisted
    if '__pub_jid' in kwargs:
        if not _check_avail(cmd):
            msg = 'This shell command is not permitted: "{0}"'.format(cmd)
            #raise CommandExecutionError(msg)
            ret = {"stdout":None,"stderr":msg,"retcode":"1","pid":None}
            return ret

    env = _parse_env(env)

    for bad_env_key in (x for x, y in six.iteritems(env) if y is None):
        log.error('Environment variable \'{0}\' passed without a value. '
                  'Setting value to an empty string'.format(bad_env_key))
        env[bad_env_key] = ''

    if runas and salt.utils.is_windows():
        if not password:
            msg = 'password is a required argument for runas on Windows'
            #raise CommandExecutionError(msg)
            ret = {"stdout":None,"stderr":msg,"retcode":"1","pid":None}
            return ret

        if not HAS_WIN_RUNAS:
            msg = 'missing salt/utils/win_runas.py'
            #raise CommandExecutionError(msg)
            ret = {"stdout":None,"stderr":msg,"retcode":"1","pid":None}
            return ret

        if not isinstance(cmd, list):
            cmd = salt.utils.shlex_split(cmd, posix=False)

        cmd = ' '.join(cmd)

        return win_runas(cmd, runas, password, cwd)

    if runas:
        # Save the original command before munging it
        try:
            pwd.getpwnam(runas)
        except KeyError:
            raise CommandExecutionError(
                'User \'{0}\' is not available'.format(runas)
            )
        try:
            # Getting the environment for the runas user
            # There must be a better way to do this.
            py_code = (
                'import sys, os, itertools; '
                'sys.stdout.write(\"\\0\".join(itertools.chain(*os.environ.items())))'
            )
            if __grains__['os'] in ['MacOS', 'Darwin']:
                env_cmd = ('sudo', '-i', '-u', runas, '--',
                           sys.executable)
            elif __grains__['os'] in ['FreeBSD']:
                env_cmd = ('su', '-', runas, '-c',
                           "{0} -c {1}".format(shell, sys.executable))
            elif __grains__['os_family'] in ['Solaris']:
                env_cmd = ('su', '-', runas, '-c', sys.executable)
            elif __grains__['os_family'] in ['AIX']:
                env_cmd = ('su', runas, '-c', sys.executable)
            else:
                env_cmd = ('su', '-s', shell, '-', runas, '-c', sys.executable)
            env_encoded = subprocess.Popen(
                env_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE
            ).communicate(py_code)[0]
            import itertools
            env_runas = dict(itertools.izip(*[iter(env_encoded.split(b'\0'))]*2))
            env_runas.update(env)
            env = env_runas
            # Encode unicode kwargs to filesystem encoding to avoid a
            # UnicodeEncodeError when the subprocess is invoked.
            fse = sys.getfilesystemencoding()
            for key, val in six.iteritems(env):
                if isinstance(val, six.text_type):
                    env[key] = val.encode(fse)
        except ValueError:
            raise CommandExecutionError(
                'Environment could not be retrieved for User \'{0}\''.format(
                    runas
                )
            )

    if _check_loglevel(output_loglevel) is not None:
        # Always log the shell commands at INFO unless quiet logging is
        # requested. The command output is what will be controlled by the
        # 'loglevel' parameter.
        msg = (
            'Executing command {0}{1}{0} {2}in directory \'{3}\'{4}'.format(
                '\'' if not isinstance(cmd, list) else '',
                cmd,
                'as user \'{0}\' '.format(runas) if runas else '',
                cwd,
                ' in the background, no output will be logged' if bg else ''
            )
        )
        log.info(log_callback(msg))

    if reset_system_locale is True:
        if not salt.utils.is_windows():
            # Default to C!
            # Salt only knows how to parse English words
            # Don't override if the user has passed LC_ALL
            env.setdefault('LC_CTYPE', 'C')
            env.setdefault('LC_NUMERIC', 'C')
            env.setdefault('LC_TIME', 'C')
            env.setdefault('LC_COLLATE', 'C')
            env.setdefault('LC_MONETARY', 'C')
            env.setdefault('LC_MESSAGES', 'C')
            env.setdefault('LC_PAPER', 'C')
            env.setdefault('LC_NAME', 'C')
            env.setdefault('LC_ADDRESS', 'C')
            env.setdefault('LC_TELEPHONE', 'C')
            env.setdefault('LC_MEASUREMENT', 'C')
            env.setdefault('LC_IDENTIFICATION', 'C')
        else:
            # On Windows set the codepage to US English.
            if python_shell:
                cmd = 'chcp 437 > nul & ' + cmd

    if clean_env:
        run_env = env
    else:
        run_env = os.environ.copy()
        run_env.update(env)

    if python_shell is None:
        python_shell = False

    kwargs = {'cwd': cwd,
              'shell': python_shell,
              'env': run_env,
              'stdin': str(stdin) if stdin is not None else stdin,
              'stdout': stdout,
              'stderr': stderr,
              'with_communicate': with_communicate,
              'timeout': timeout,
              'bg': bg,
              }

    if umask is not None:
        _umask = str(umask).lstrip('0')

        if _umask == '':
            msg = 'Zero umask is not allowed.'
            raise CommandExecutionError(msg)

        try:
            _umask = int(_umask, 8)
        except ValueError:
            msg = 'Invalid umask: \'{0}\''.format(umask)
            raise CommandExecutionError(msg)
    else:
        _umask = None

    if runas or umask:
        kwargs['preexec_fn'] = functools.partial(
            salt.utils.chugid_and_umask,
            runas,
            _umask)

    if not salt.utils.is_windows():
        # close_fds is not supported on Windows platforms if you redirect
        # stdin/stdout/stderr
        if kwargs['shell'] is True:
            kwargs['executable'] = shell
        kwargs['close_fds'] = True

    if not os.path.isabs(cwd) or not os.path.isdir(cwd):
        #raise CommandExecutionError(
        #    'Specified cwd \'{0}\' either not absolute or does not exist'
        #    .format(cwd)
        #)
        msg = 'Specified cwd \'{0}\' either not absolute or does not exist'.format(cwd)
        ret = {"stdout":None,"stderr":msg,"retcode":"1","pid":None}
        return ret
            

    if python_shell is not True and not isinstance(cmd, list):
        posix = True
        if salt.utils.is_windows():
            posix = False
        cmd = salt.utils.shlex_split(cmd, posix=posix)
    if not use_vt:
        # This is where the magic happens
        ret_str = ""
        ret_err = ""
        ret_code = 0
        cmd_status_code = "1"  # command execute status code
        su_status_code = "1"  # switch user cmd execut  status code
        #shell_fullpath = DEFAULT_SHELL
        if shell_fullpath is None:
            shell_fullpath = shell
        if '\n' in cmd:
            cmd_input = cmd.replace("\n",";")
            cmd_name = shell_fullpath + ' -c ' + '\'' + cmd_input + '\'' + ';echo $?' 
        else:
            cmd_name = shell_fullpath + ' -c ' + '\'' + cmd + '\'' + ';echo $?' 
        log.debug('cmd excution line \'{0}\''.format(cmd_name))
        if su_method == "su":
            su_prefix = 'su -'
        elif su_method == "sudo":
            su_prefix = 'sudo'
        # wrong_su_method = 'su1234'
        # only support su right now
        try:
            child = pexpect.spawn(su_prefix + ' ' + su_user)
            index = child.expect(["Password", pexpect.EOF, pexpect.TIMEOUT])
            if index == 0:
                child.sendline(password)
                index_pwd_verified = child.expect(["[Pp]assword", '\[.+', "incorrect password",
                                                   pexpect.EOF, pexpect.TIMEOUT])
                if index_pwd_verified == 1:
                    su_status_code = "0"  # switch user ok
                    if kwargs.get("cwd"):
                        child.sendline('cd ' + kwargs.get("cwd"))
                        index_cwd = child.expect(["[Pp]assword", '\[.+', "incorrect password",
                                                   pexpect.EOF, pexpect.TIMEOUT])
                        if index_cwd != 1:
                            ret_err = "change dir to %s failed " % kwargs.get("cwd")
                        else:
                            child.sendline(cmd_name)
                            child.expect('\[.+')
                            raw_output = child.before
                    else:
                        child.sendline(cmd_name)
                        child.expect('\[.+')
                        raw_output = child.before
                    log.debug('command output \'{0}\''.format(raw_output))
                    cmd_result_list = raw_output.split('\r\n')
                    cmd_result_list.pop()
                    cmd_status_code = str(cmd_result_list.pop())
                    #ret_str = cmd_result_list[1:]
                    for line in cmd_result_list[1:]:
                        ret_str = ret_str + line + '\n' 
                    child.sendline('exit')
                elif index_pwd_verified == 2:
                    ret_err = "You entered an invalid su password. password verify failed cannot switch user"
                else:
                    ret_err = "su password verify failed, due to TIMEOUT or EOF"
                child.close(force=True)
            else:
                # something wrong
                # print '########'
                ret_err = "su to user: %s failed, due to TIMEOUT or EOF" % username
            if su_status_code == "0" and cmd_status_code == "0":
                ret_code = 0  # switch user and command execute are all successful
            else:
                ret_code = 1
        except pexpect.exceptions.ExceptionPexpect as e:
            ret_err = str(e)
            ret_code = 1
        #if rstrip:
        #    if ret_str is not None:
        #        ret_str = salt.utils.to_str(ret_str).rstrip()
        #    if ret_err is not None:
        #        ret_err = salt.utils.to_str(ret_err).rstrip()
        ret['pid'] = None
        ret['retcode'] = ret_code
        ret['stdout'] = ret_str
        ret['stderr'] = ret_err
    else:
        log.debug("unsuported operations")
        ret['pid'] = None
        ret['retcode'] = "1"
        ret['stdout'] = None
        ret['stderr'] = "unsupport operation"
    try:
        if ignore_retcode:
            __context__['retcode'] = 0
        else:
            __context__['retcode'] = ret['retcode']
    except NameError:
        # Ignore the context error during grain generation
        pass
    return ret


def su_run_all(cmd,
            cwd=None,
            stdin=None,
            runas=None,
            su_user=None,
            su_method="su",
            password=None,
            shell=DEFAULT_SHELL,
            python_shell=None,
            env=None,
            clean_env=False,
            template=None,
            rstrip=True,
            umask=None,
            output_loglevel='debug',
            log_callback=None,
            timeout=None,
            reset_system_locale=True,
            ignore_retcode=False,
            saltenv='base',
            use_vt=False,
            redirect_stderr=False,
            **kwargs):

    python_shell = _python_shell_default(python_shell,
                                         kwargs.get('__pub_jid', ''))
    stderr = subprocess.STDOUT if redirect_stderr else subprocess.PIPE
    
    ret = _su_run(cmd,
               runas=runas,
               su_user=su_user,
               su_method=su_method,
               password=password,
               cwd=cwd,
               stdin=stdin,
               stderr=stderr,
               shell=shell,
               python_shell=python_shell,
               env=env,
               clean_env=clean_env,
               template=template,
               rstrip=rstrip,
               umask=umask,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               ignore_retcode=ignore_retcode,
               saltenv=saltenv,
               use_vt=use_vt,
               **kwargs)

    log_callback = _check_cb(log_callback)

    lvl = _check_loglevel(output_loglevel)
    if lvl is not None:
        if not ignore_retcode and int(ret['retcode']) != 0:
            if lvl < LOG_LEVELS['error']:
                lvl = LOG_LEVELS['error']
            msg = (
                'Command \'{0}\' failed with return code: {1}'.format(
                    cmd,
                    ret['retcode']
                )
            )
            log.error(log_callback(msg))
        if ret['stdout']:
            log.log(lvl, 'stdout: {0}'.format(log_callback(ret['stdout'])))
        if ret['stderr']:
            log.log(lvl, 'stderr: {0}'.format(log_callback(ret['stderr'])))
        if ret['retcode']:
            log.log(lvl, 'retcode: {0}'.format(ret['retcode']))
    log.debug(ret)
    return ret


def retcode(cmd,
            cwd=None,
            stdin=None,
            runas=None,
            su_user=None,
            su_method="su",
            password=None,
            shell=DEFAULT_SHELL,
            python_shell=None,
            env=None,
            rstrip=True,
            clean_env=False,
            template=None,
            umask=None,
            output_loglevel='debug',
            log_callback=None,
            timeout=None,
            reset_system_locale=True,
            ignore_retcode=False,
            saltenv='base',
            use_vt=False,
            **kwargs):
    ret = _su_run(cmd,
               runas=runas,
               su_user=su_user,
               su_method=su_method,
               password=password,
               cwd=cwd,
               stdin=stdin,
               shell=shell,
               python_shell=python_shell,
               env=env,
               clean_env=clean_env,
               template=template,
               rstrip=rstrip,
               umask=umask,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               ignore_retcode=ignore_retcode,
               saltenv=saltenv,
               use_vt=use_vt,
               **kwargs)
    
    log_callback = _check_cb(log_callback)
    lvl = _check_loglevel(output_loglevel)
    if lvl is not None:
        if not ignore_retcode and ret['retcode'] != 0:
            if lvl < LOG_LEVELS['error']:
                lvl = LOG_LEVELS['error']
            msg = (
                'Command \'{0}\' failed with return code: {1}'.format(
                    cmd,
                    ret['retcode']
                )
            )
            log.error(log_callback(msg))
        log.log(lvl, 'output: {0}'.format(log_callback(ret['stdout'])))
    return ret['retcode']


def script(source,
           args=None,
           cwd=None,
           stdin=None,
           runas=None,
           su_user=None,
           su_method="su",
           password=None,
           shell=DEFAULT_SHELL,
           python_shell=None,
           env=None,
           template=None,
           umask=None,
           output_loglevel='debug',
           log_callback=None,
           quiet=False,
           timeout=None,
           reset_system_locale=True,
           saltenv='base',
           use_vt=False,
           bg=False,
           **kwargs):
    python_shell = _python_shell_default(python_shell,
                                         kwargs.get('__pub_jid', ''))

    def _cleanup_tempfile(path):
        try:
            os.remove(path)
        except (IOError, OSError) as exc:
            log.error(
                'cmd.script: Unable to clean tempfile \'{0}\': {1}'.format(
                    path,
                    exc
                )
            )

    if '__env__' in kwargs:
        salt.utils.warn_until(
            'Oxygen',
            'Parameter \'__env__\' has been detected in the argument list.  This '
            'parameter is no longer used and has been replaced by \'saltenv\' '
            'as of Salt Carbon.  This warning will be removed in Salt Oxygen.'
            )
        kwargs.pop('__env__')

    path = salt.utils.mkstemp(dir=cwd, suffix=os.path.splitext(source)[1])

    if template:
        if 'pillarenv' in kwargs or 'pillar' in kwargs:
            pillarenv = kwargs.get('pillarenv', __opts__.get('pillarenv'))
            kwargs['pillar'] = _gather_pillar(pillarenv, kwargs.get('pillar'))
        fn_ = __salt__['cp.get_template'](source,
                                          path,
                                          template,
                                          saltenv,
                                          **kwargs)
        if not fn_:
            _cleanup_tempfile(path)
            return {'pid': 0,
                    'retcode': 1,
                    'stdout': '',
                    'stderr': '',
                    'cache_error': True}
    else:
        fn_ = __salt__['cp.cache_file'](source, saltenv)
        if not fn_:
            _cleanup_tempfile(path)
            return {'pid': 0,
                    'retcode': 1,
                    'stdout': '',
                    'stderr': '',
                    'cache_error': True}
        shutil.copyfile(fn_, path)
    if not salt.utils.is_windows():
        os.chmod(path, 320)
        os.chown(path, __salt__['file.user_to_uid'](runas), -1)
    ret = _su_run(path + ' ' + str(args) if args else path,
               cwd=cwd,
               stdin=stdin,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               runas=runas,
               su_user=su_user,
               su_method=su_method,
               password=password,
               shell=shell,
               python_shell=python_shell,
               env=env,
               umask=umask,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               saltenv=saltenv,
               use_vt=use_vt,
               bg=bg,
               **kwargs)
    _cleanup_tempfile(path)
    return ret
