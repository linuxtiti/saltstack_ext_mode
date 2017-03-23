# -*- coding: utf-8 -*-

"""
switch user state module


"""

# Import python libs
from __future__ import absolute_import

import os
import copy
import json
import logging
from collections import OrderedDict


# Import salt libs
import salt.utils
from salt.exceptions import CommandExecutionError, SaltRenderError
from salt.ext.six import string_types

log = logging.getLogger(__name__)
su_cmd_state_version = "0.16-dev"


def display_ver(name):
    #return su_cmd_state_version
    ret = {
        'name': name,
        'changes': OrderedDict(),
        'result': True,
        'comment': ''}
    try:
        execute_info_dict = __salt__['su_cmd.display_ver']()
    except Exception:
        execute_info_dict = {}
    ret['changes']["su run state module"] = __name__
    ret['changes']["su run state module version"] = su_cmd_state_version
    ret['changes']["su run excution module"] = execute_info_dict.get("name")
    ret['changes']["su run excution module version"] = execute_info_dict.get("version")
    
    return ret


def _reinterpreted_state(state):
    '''
    Re-interpret the state returned by salt.state.run using our protocol.
    '''
    ret = state['changes']
    state['changes'] = {}
    state['comment'] = ''

    out = ret.get('stdout')
    if not out:
        if ret.get('stderr'):
            state['comment'] = ret['stderr']
        return state

    is_json = False
    try:
        data = json.loads(out)
        if not isinstance(data, dict):
            return _failout(
                state,
                'script JSON output must be a JSON object (e.g., {})!'
            )
        is_json = True
    except ValueError:
        idx = out.rstrip().rfind('\n')
        if idx != -1:
            out = out[idx + 1:]
        data = {}
        try:
            for item in salt.utils.shlex_split(out):
                key, val = item.split('=')
                data[key] = val
        except ValueError:
            state = _failout(
                state,
                'Failed parsing script output! '
                'Stdout must be JSON or a line of name=value pairs.'
            )
            state['changes'].update(ret)
            return state

    changed = _is_true(data.get('changed', 'no'))

    if 'comment' in data:
        state['comment'] = data['comment']
        del data['comment']

    if changed:
        for key in ret:
            data.setdefault(key, ret[key])

        # if stdout is the state output in JSON, don't show it.
        # otherwise it contains the one line name=value pairs, strip it.
        data['stdout'] = '' if is_json else data.get('stdout', '')[:idx]
        state['changes'] = data

    #FIXME: if it's not changed but there's stdout and/or stderr then those
    #       won't be shown as the function output. (though, they will be shown
    #       inside INFO logs).
    return state


def _failout(state, msg):
    state['comment'] = msg
    state['result'] = False
    return state


def _is_true(val):
    if val and str(val).lower() in ('true', 'yes', '1'):
        return True
    elif str(val).lower() in ('false', 'no', '0'):
        return False
    raise ValueError('Failed parsing boolean value: {0}'.format(val))


def mod_run_check(cmd_kwargs, onlyif, unless, creates,su_user,su_password):
    '''
    Execute the onlyif and unless logic.
    Return a result dict if:
    * onlyif failed (onlyif != 0)
    * unless succeeded (unless == 0)
    else return True
    '''
    # never use VT for onlyif/unless executions because this will lead
    # to quote problems
    cmd_kwargs = copy.deepcopy(cmd_kwargs)
    cmd_kwargs['use_vt'] = False

    if onlyif is not None:
        if isinstance(onlyif, string_types):
            cmd = __salt__['su_cmd.retcode'](onlyif, ignore_retcode=True,su_user=su_user,password=su_password,
                python_shell=True, **cmd_kwargs)
            log.debug('Last command return code: {0}'.format(cmd))
            if cmd != 0:
                return {'comment': 'onlyif execution failed',
                        'skip_watch': True,
                        'result': True}
        elif isinstance(onlyif, list):
            for entry in onlyif:
                cmd = __salt__['su_cmd.retcode'](entry, ignore_retcode=True, su_user=su_user,password=su_password,
                    python_shell=True, **cmd_kwargs)
                log.debug('Last command return code: {0}'.format(cmd))
                if cmd != 0:
                    return {'comment': 'onlyif execution failed',
                        'skip_watch': True,
                        'result': True}
        elif not isinstance(onlyif, string_types):
            if not onlyif:
                log.debug('Command not run: onlyif did not evaluate to string_type')
                return {'comment': 'onlyif execution failed',
                        'skip_watch': True,
                        'result': True}

    if unless is not None:
        if isinstance(unless, string_types):
            cmd = __salt__['su_cmd.retcode'](unless, ignore_retcode=True, su_user=su_user,password=su_password,
                python_shell=True, **cmd_kwargs)
            log.debug('Last command return code: {0}'.format(cmd))
            if cmd == 0:
                return {'comment': 'unless execution succeeded',
                        'skip_watch': True,
                        'result': True}
        elif isinstance(unless, list):
            cmd = []
            for entry in unless:
                cmd.append(__salt__['su_cmd.retcode'](entry, ignore_retcode=True, su_user=su_user,password=su_password,
                    python_shell=True, **cmd_kwargs))
                log.debug('Last command return code: {0}'.format(cmd))
                if all([c == 0 for c in cmd]):
                    return {'comment': 'unless execution succeeded',
                            'skip_watch': True,
                            'result': True}
        elif not isinstance(unless, string_types):
            if unless:
                log.debug('Command not run: unless did not evaluate to string_type')
                return {'comment': 'unless execution succeeded',
                        'skip_watch': True,
                        'result': True}

    if isinstance(creates, string_types) and os.path.exists(creates):
        return {'comment': '{0} exists'.format(creates),
                'result': True}
    elif isinstance(creates, list) and all([
        os.path.exists(path) for path in creates
    ]):
        return {'comment': 'All files in creates exist',
                'result': True}

    # No reason to stop, return True
    return True


def run(name,
        onlyif=None,
        unless=None,
        creates=None,
        cwd=None,
        runas=None,
        shell=None,
        env=None,
        stateful=False,
        umask=None,
        output_loglevel='debug',
        quiet=False,
        timeout=None,
        ignore_timeout=False,
        use_vt=False,
        su_user=None,
        su_method="su",
        su_password=None,
        **kwargs):
    '''
    Run a command if certain circumstances are met.  Use ``cmd.wait`` if you
    want to use the ``watch`` requisite.

    name
        The command to execute, remember that the command will execute with the
        path and permissions of the salt-minion.

    onlyif
        A command to run as a check, run the named command only if the command
        passed to the ``onlyif`` option returns true

    unless
        A command to run as a check, only run the named command if the command
        passed to the ``unless`` option returns false

    cwd
        The current working directory to execute the command in, defaults to
        /root

    runas
        The user name to run the command as

    shell
        The shell to use for execution, defaults to the shell grain

    env
        A list of environment variables to be set prior to execution.
        Example:

        .. code-block:: yaml

            script-foo:
              cmd.run:
                - env:
                  - BATCH: 'yes'

        .. warning::

            The above illustrates a common PyYAML pitfall, that **yes**,
            **no**, **on**, **off**, **true**, and **false** are all loaded as
            boolean ``True`` and ``False`` values, and must be enclosed in
            quotes to be used as strings. More info on this (and other) PyYAML
            idiosyncrasies can be found :doc:`here
            </topics/troubleshooting/yaml_idiosyncrasies>`.

        Variables as values are not evaluated. So $PATH in the following
        example is a literal '$PATH':

        .. code-block:: yaml

            script-bar:
              cmd.run:
                - env: "PATH=/some/path:$PATH"

        One can still use the existing $PATH by using a bit of Jinja:

        .. code-block:: yaml

            {% set current_path = salt['environ.get']('PATH', '/bin:/usr/bin') %}

            mycommand:
              cmd.run:
                - name: ls -l /
                - env:
                  - PATH: {{ [current_path, '/my/special/bin']|join(':') }}

    stateful
        The command being executed is expected to return data about executing
        a state. For more information, see the :ref:`stateful-argument` section.

    umask
        The umask (in octal) to use when running the command.

    output_loglevel
        Control the loglevel at which the output from the command is logged.
        Note that the command being run will still be logged (loglevel: DEBUG)
        regardless, unless ``quiet`` is used for this value.

    quiet
        The command will be executed quietly, meaning no log entries of the
        actual command or its return data. This is deprecated as of the
        **2014.1.0** release, and is being replaced with
        ``output_loglevel: quiet``.

    timeout
        If the command has not terminated after timeout seconds, send the
        subprocess sigterm, and if sigterm is ignored, follow up with sigkill

    ignore_timeout
        Ignore the timeout of commands, which is useful for running nohup
        processes.

        .. versionadded:: 2015.8.0

    creates
        Only run if the file specified by ``creates`` does not exist.

        .. versionadded:: 2014.7.0

    use_vt
        Use VT utils (saltstack) to stream the command output more
        interactively to the console and the logs.
        This is experimental.

    .. note::

        cmd.run supports the usage of ``reload_modules``. This functionality
        allows you to force Salt to reload all modules. You should only use
        ``reload_modules`` if your cmd.run does some sort of installation
        (such as ``pip``), if you do not reload the modules future items in
        your state which rely on the software being installed will fail.

        .. code-block:: yaml

            getpip:
              cmd.run:
                - name: /usr/bin/python /usr/local/sbin/get-pip.py
                - unless: which pip
                - require:
                  - pkg: python
                  - file: /usr/local/sbin/get-pip.py
                - reload_modules: True

    '''
    ### NOTE: The keyword arguments in **kwargs are ignored in this state, but
    ###       cannot be removed from the function definition, otherwise the use
    ###       of unsupported arguments in a cmd.run state will result in a
    ###       traceback.

    test_name = None
    if not isinstance(stateful, list):
        stateful = stateful is True
    elif isinstance(stateful, list) and 'test_name' in stateful[0]:
        test_name = stateful[0]['test_name']
    if __opts__['test'] and test_name:
        name = test_name

    ret = {'name': name,
           'changes': {},
           'result': False,
           'comment': ''}

    # Need the check for None here, if env is not provided then it falls back
    # to None and it is assumed that the environment is not being overridden.
    if env is not None and not isinstance(env, (list, dict)):
        ret['comment'] = ('Invalidly-formatted \'env\' parameter. See '
                          'documentation.')
        return ret

    if 'user' in kwargs or 'group' in kwargs:
        salt.utils.warn_until(
            'Oxygen',
            'The legacy user/group arguments are deprecated. '
            'Replace them with runas. '
            'These arguments will be removed in Salt Oxygen.'
        )
        if 'user' in kwargs and kwargs['user'] is not None and runas is None:
            runas = kwargs.pop('user')

    cmd_kwargs = copy.deepcopy(kwargs)
    cmd_kwargs.update({'cwd': cwd,
                       'runas': runas,
                       'use_vt': use_vt,
                       'shell': shell or __grains__['shell'],
                       'env': env,
                       'umask': umask,
                       'output_loglevel': output_loglevel,
                       'quiet': quiet})

    cret = mod_run_check(cmd_kwargs, onlyif, unless, creates,su_user,su_password)
    if isinstance(cret, dict):
        ret.update(cret)
        return ret

    if __opts__['test'] and not test_name:
        ret['result'] = None
        ret['comment'] = 'Command "{0}" would have been executed'.format(name)
        return _reinterpreted_state(ret) if stateful else ret

    if cwd and not os.path.isdir(cwd):
        ret['comment'] = (
            'Desired working directory "{0}" '
            'is not available'
        ).format(cwd)
        return ret

    # Wow, we passed the test, run this sucker!
    try:
        cmd_all = __salt__['su_cmd.su_run_all'](
            name, timeout=timeout, python_shell=True,su_user=su_user,su_method=su_method,
                       password=su_password,**cmd_kwargs
        )
    except CommandExecutionError as err:
        ret['comment'] = str(err)
        return ret

    ret['changes'] = cmd_all
    ret['result'] = not bool(cmd_all['retcode'])
    ret['comment'] = 'Command "{0}" run'.format(name)

    # Ignore timeout errors if asked (for nohups) and treat cmd as a success
    if ignore_timeout:
        trigger = 'Timed out after'
        if ret['changes'].get('retcode') == 1 and trigger in ret['changes'].get('stdout'):
            ret['changes']['retcode'] = 0
            ret['result'] = True

    if stateful:
        ret = _reinterpreted_state(ret)
    if __opts__['test'] and cmd_all['retcode'] == 0 and ret['changes']:
        ret['result'] = None
    return ret


def script(name,
           source=None,
           args=None,
           template=None,
           onlyif=None,
           unless=None,
           creates=None,
           cwd=None,
           runas=None,
           shell=None,
           env=None,
           stateful=False,
           umask=None,
           timeout=None,
           use_vt=False,
           output_loglevel='warning',
           defaults=None,
           context=None,
           su_user=None,
           su_method="su",
           su_password=None,
           **kwargs):
    '''
    Download a script and execute it with specified arguments.

    source
        The location of the script to download. If the file is located on the
        master in the directory named spam, and is called eggs, the source
        string is salt://spam/eggs

    template
        If this setting is applied then the named templating engine will be
        used to render the downloaded file. Currently jinja, mako, and wempy
        are supported

    name
        Either "cmd arg1 arg2 arg3..." (cmd is not used) or a source
        "salt://...".

    onlyif
        Run the named command only if the command passed to the ``onlyif``
        option returns true

    unless
        Run the named command only if the command passed to the ``unless``
        option returns false

    cwd
        The current working directory to execute the command in, defaults to
        /root

    runas
        The name of the user to run the command as

    shell
        The shell to use for execution. The default is set in grains['shell']

    env
        A list of environment variables to be set prior to execution.
        Example:

        .. code-block:: yaml

            salt://scripts/foo.sh:
              cmd.script:
                - env:
                  - BATCH: 'yes'

        .. warning::

            The above illustrates a common PyYAML pitfall, that **yes**,
            **no**, **on**, **off**, **true**, and **false** are all loaded as
            boolean ``True`` and ``False`` values, and must be enclosed in
            quotes to be used as strings. More info on this (and other) PyYAML
            idiosyncrasies can be found :doc:`here
            </topics/troubleshooting/yaml_idiosyncrasies>`.

        Variables as values are not evaluated. So $PATH in the following
        example is a literal '$PATH':

        .. code-block:: yaml

            salt://scripts/bar.sh:
              cmd.script:
                - env: "PATH=/some/path:$PATH"

        One can still use the existing $PATH by using a bit of Jinja:

        .. code-block:: yaml

            {% set current_path = salt['environ.get']('PATH', '/bin:/usr/bin') %}

            mycommand:
              cmd.run:
                - name: ls -l /
                - env:
                  - PATH: {{ [current_path, '/my/special/bin']|join(':') }}

    saltenv : ``base``
        The Salt environment to use

    umask
         The umask (in octal) to use when running the command.

    stateful
        The command being executed is expected to return data about executing
        a state. For more information, see the :ref:`stateful-argument` section.

    timeout
        If the command has not terminated after timeout seconds, send the
        subprocess sigterm, and if sigterm is ignored, follow up with sigkill

    args
        String of command line args to pass to the script.  Only used if no
        args are specified as part of the `name` argument. To pass a string
        containing spaces in YAML, you will need to doubly-quote it:  "arg1
        'arg two' arg3"

    creates
        Only run if the file or files specified by ``creates`` do not exist.

        .. versionadded:: 2014.7.0

    use_vt
        Use VT utils (saltstack) to stream the command output more
        interactively to the console and the logs.
        This is experimental.

    context
        .. versionadded:: 2016.3.0

        Overrides default context variables passed to the template.

    defaults
        .. versionadded:: 2016.3.0

        Default context passed to the template.

    output_loglevel
        Control the loglevel at which the output from the command is logged.
        Note that the command being run will still be logged (loglevel: DEBUG)
        regardless, unless ``quiet`` is used for this value.

    '''
    test_name = None
    if not isinstance(stateful, list):
        stateful = stateful is True
    elif isinstance(stateful, list) and 'test_name' in stateful[0]:
        test_name = stateful[0]['test_name']
    if __opts__['test'] and test_name:
        name = test_name

    ret = {'name': name,
           'changes': {},
           'result': False,
           'comment': ''}

    # Need the check for None here, if env is not provided then it falls back
    # to None and it is assumed that the environment is not being overridden.
    if env is not None and not isinstance(env, (list, dict)):
        ret['comment'] = ('Invalidly-formatted \'env\' parameter. See '
                          'documentation.')
        return ret

    if context and not isinstance(context, dict):
        ret['comment'] = ('Invalidly-formatted \'context\' parameter. Must '
                          'be formed as a dict.')
        return ret
    if defaults and not isinstance(defaults, dict):
        ret['comment'] = ('Invalidly-formatted \'defaults\' parameter. Must '
                          'be formed as a dict.')
        return ret

    tmpctx = defaults if defaults else {}
    if context:
        tmpctx.update(context)

    if 'user' in kwargs or 'group' in kwargs:
        salt.utils.warn_until(
            'Oxygen',
            'The legacy user/group arguments are deprecated. '
            'Replace them with runas. '
            'These arguments will be removed in Salt Oxygen.'
        )
        if 'user' in kwargs and kwargs['user'] is not None and runas is None:
            runas = kwargs.pop('user')

    cmd_kwargs = copy.deepcopy(kwargs)
    cmd_kwargs.update({'runas': runas,
                       'shell': shell or __grains__['shell'],
                       'env': env,
                       'onlyif': onlyif,
                       'unless': unless,
                       'cwd': cwd,
                       'template': template,
                       'umask': umask,
                       'timeout': timeout,
                       'output_loglevel': output_loglevel,
                       'use_vt': use_vt,
                       'context': tmpctx,
                       'saltenv': __env__})

    run_check_cmd_kwargs = {
        'cwd': cwd,
        'runas': runas,
        'shell': shell or __grains__['shell']
    }

    # Change the source to be the name arg if it is not specified
    if source is None:
        source = name

    # If script args present split from name and define args
    #if len(name.split()) > 1:
    #    cmd_kwargs.update({'args': name.split(' ', 1)[1]})

    cret = mod_run_check(
        run_check_cmd_kwargs, onlyif, unless, creates,su_user,su_password
    )
    if isinstance(cret, dict):
        ret.update(cret)
        return ret

    if __opts__['test'] and not test_name:
        ret['result'] = None
        ret['comment'] = 'Command \'{0}\' would have been ' \
                         'executed'.format(name)
        return _reinterpreted_state(ret) if stateful else ret

    if cwd and not os.path.isdir(cwd):
        ret['comment'] = (
            'Desired working directory "{0}" '
            'is not available'
        ).format(cwd)
        return ret

    # Wow, we passed the test, run this sucker!
    try:
        cmd_all = __salt__['su_cmd.script'](source,args,su_user=su_user,su_method=su_method,password=su_password,
                                             python_shell=True, **cmd_kwargs)
    except (CommandExecutionError, SaltRenderError, IOError) as err:
        ret['comment'] = str(err)
        return ret

    ret['changes'] = cmd_all
    if kwargs.get('retcode', False):
        ret['result'] = not bool(cmd_all)
    else:
        ret['result'] = not bool(cmd_all['retcode'])
    if ret.get('changes', {}).get('cache_error'):
        ret['comment'] = 'Unable to cache script {0} from saltenv ' \
                         '\'{1}\''.format(source, __env__)
    else:
        ret['comment'] = 'Command \'{0}\' run'.format(name)
    if stateful:
        ret = _reinterpreted_state(ret)
    if __opts__['test'] and cmd_all['retcode'] == 0 and ret['changes']:
        ret['result'] = None
    return ret
