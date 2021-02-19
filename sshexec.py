import asyncio
import logging
import threading
from collections import defaultdict
from functools import partial, wraps
from inspect import signature
from pprint import pformat
from typing import Dict, Union

import asyncssh


def init_logger():
    handler = logging.StreamHandler()
    log_format = u'%(asctime)s [%(levelname)-1s %(process)d %(threadName)s]  %(message)s'
    handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


logger = logging.getLogger("SSHExec")
init_logger()

Hostname = str
SSH_EXEC__CONNECTIONS_PER_HOST = 10
DEFAULT_SFTP_TIMEOUT = 3600
DEFAULT_SSH_TIMEOUT = 30


def needs_loop(func):
    """
    A safeguard decorator for methods that require a live event loop.
    Inner function is needed to capture the instance reference -
    when needs_loop() is executed, there is no instance yet (hence no 'self')
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        self = args[0]
        if not self.loop.is_running():
            raise Exception("Cannot submit task to a stopped loop.")
        return func(*args, **kwargs)

    return wrapper


class ReprMixin(object):
    """
    Mixin class for all SSHExec classes for __repr__ protocol
    """

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, pformat(self.__dict__))


class AuthInfo(ReprMixin):
    """
    Authentication Information of the command sender
    """

    def __init__(self, hostname=None, username=None, password=None, port=22):
        """
        :param hostname: str, IP to server to run the command on
        :param username: str, username
        :param password: str, password
        :param port: int, SSH Port (Default 22)
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port

    def __repr__(self):
        return f"({self.__class__.__name__})- {self.hostname}:{self.port}, {self.username}/{self.password})"


class CmdInfo(AuthInfo):
    """
    Command Information
    """

    def __init__(self, cmd_string=None, timeout=None, response=None, has_banner=False, **kwargs):
        """
        :param cmd_string: str, Command to run
        :param timeout: int, Timeout for the command
        :param response: str, Response to answer in case on interactive command
        :param has_banner: bool, True iff command has banner before getting the result
        :param kwargs: kwargs
        """
        super().__init__(**kwargs)
        self.has_banner = has_banner
        self.cmd_string = cmd_string
        self.timeout = timeout
        self.response = response


class ResultInfo(ReprMixin):
    """
    Result Information
    """

    def __init__(self, *, stdout=None, stderr=None, rc=None, cmd_string=None, timed_out=False):
        """
        :param stdout: str, output stream
        :param stderr: str, stderr
        :param rc: int, RC
        :param cmd_string: str, Sent command
        :param timed_out: bool, True iff command was timed out
        """
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc
        self.cmd = cmd_string
        self.timed_out = timed_out

    def __repr__(self):
        return f"(cmd={self.cmd}, RC={self.rc}, TO={self.timed_out}, stdout={self.stdout}, stderr={self.stderr}"


class AsyncConnInfo(ReprMixin):
    """
    Connection information
    """

    def __init__(self, connection, client, semaphore):
        """
        :param connection: Connection object
        :param client:  Client object
        :param semaphore: Semaphore
        """
        self.connection = connection
        self.client = client
        self.semaphore = semaphore  # type: asyncio.Semaphore


def log_debug(*args, **kwargs):
    """
    By default - outputs nothing. Uncomment one of the lines below as needed.
    """
    pass


class SSHClient(asyncssh.SSHClient):
    """
    Implements disconnection handling, and some debug functionality
    """

    def __init__(self):
        self.connected = False
        self.host = None
        super().__init__()

    def connection_made(self, connection: asyncssh.SSHClientConnection):
        """
        Function that runs after a connection was made

        :param connection: Connection was made
        :type connection: asyncssh.SSHClientConnection
        :return: None
        """
        self.host = connection._host
        log_debug("Made TCP connection to: {}".format(self.host))
        # check_conn_cmd = "echo {}".format(self.host)
        # connection.create_task(check_conn_cmd).result()
        # reply = asyncio.run_coroutine_threadsafe(SSHExec.execute_ssh(connection, check_conn_cmd), loop=
        #                                          SSHExec.loop).result()
        # log_debug("Testing connection, sent {}, received: {}".format(check_conn_cmd, reply))

    def connection_lost(self, exc: Exception):
        """
        Function that runs after a connection was lost

        :param exc: Exception thrown after lost connection
        :type exc: Exception
        :return: Noneloglog
        """
        log_debug("Lost connection to: {}, reason: {}".format(self.host, exc))
        self.connected = False

    def auth_completed(self):
        """
        Function that after authentication was completed

        :return: None
        """
        self.connected = True
        log_debug("Connected to : {}".format(self.host))


class _SSHExec(threading.Thread):
    """
    Keep in mind that SSH server has a default value for maximum concurrent connections (usually 10).
    If connections_per_host exceed this value, connection requests might be refused and
    commands will silently fail due to the current way ssh connection exceptions are handled in the OS layer.
    """

    def __init__(self, connections_per_host=SSH_EXEC__CONNECTIONS_PER_HOST, debug_flag=False,
                 *args, **kwargs):
        if 'name' not in kwargs:
            kwargs.update({'name': "SSHExec EventLoop"})
        threading.Thread.__init__(self, daemon=True, *args, **kwargs)
        self.loop = None  # type: Union[asyncio.BaseEventLoop, None]
        self.conn_dict = {}  # type: Dict[Hostname, AsyncConnInfo]
        self.debug_flag = debug_flag
        self.connections_per_host = connections_per_host
        self.is_running = threading.Event()
        self.coro_conn_locks = None  # type: Union[Dict[Hostname, asyncio.Lock], None]
        log_debug("Initialize SSHExec")

    def __str__(self):
        return self.__hash__()

    def __repr__(self):
        return self.__str__()

    def reset(self):
        log_debug("Reset SSHExec: {}".format(self.name))
        self.conn_dict = {}
        self.coro_conn_locks = defaultdict(partial(asyncio.Lock, loop=self.loop))

    def run_me(self):
        SSHExec.start()
        SSHExec.is_running.wait()
        log_debug("Started {}".format(SSHExec.name))

    def run(self):
        """
        These actions take place on the event loop thread
        not on the main (calling) thread
        """
        self.loop = asyncio.new_event_loop()  # type: asyncio.BaseEventLoop
        asyncio.set_event_loop(self.loop)
        asyncio.BaseEventLoop.set_debug(self.loop, enabled=self.debug_flag)
        self.coro_conn_locks = defaultdict(partial(asyncio.Lock, loop=self.loop))  # type: Dict[Hostname, asyncio.Lock]
        # Once the loop starts, is_up will be set
        self.loop.call_soon(self.is_running.set)
        self.loop.run_forever()

    def stop(self):
        """ Stop SSHExec """
        log_debug("Stopping {}".format(self.name))
        self.is_running.clear()
        self.loop.call_soon_threadsafe(self.loop.stop)

    @needs_loop
    def sftp(self, auth_info: AuthInfo):
        """
        An sftp_proxy factory, each sftp_proxy instance has the connection
        credentials and the event loop thread (self above)
        baked into __getattr__ on instantiation.
        This allows the OSL layer to provide the credentials in
        a way that is transparent to the test writer who only needs to
        provide the arguments that are specific to the sftp method he wants
        to execute.
        Verification of required sftp parameters/correct sftp method name
        is performed inside __getattr__, before forwarding the actual
        execution to the event loop so that param/name related exceptions
        are raised in the calling thread and not in the event loop thread.
        """

        class SFTPProxy(object):
            @staticmethod
            def __getattr__(sftp_method_name: str):
                def sftp_proxy_cmd(**kwargs):
                    sftp_method_obj = getattr(asyncssh.SFTPClient, sftp_method_name)
                    param_val_pairs = {param_name: kwargs[param_name]
                                       for param_name in
                                       signature(sftp_method_obj).parameters
                                       if param_name in kwargs}
                    sftp_func = partial(sftp_method_obj, **param_val_pairs)
                    asftp_cmd = self.async_sftp_cmd(sftp_func, auth_info)
                    fut = asyncio.run_coroutine_threadsafe(asftp_cmd, loop=self.loop)
                    return fut.result(timeout=DEFAULT_SFTP_TIMEOUT)

                return sftp_proxy_cmd

        return SFTPProxy()

    async def async_sftp_cmd(self, sftp_func, auth_info: AuthInfo):
        conn_info = await self.get_connection(auth_info)
        with await conn_info.semaphore, await conn_info.connection.start_sftp_client() as sftp_client:
            return await sftp_func(self=sftp_client)

    def is_connected(self, auth_info: AuthInfo, timeout: int = 5) -> bool:
        """
        :param auth_info: Authentication information
        :type auth_info: AuthInfo
        :param timeout: Command timeout
        :type timeout: int
        :return: True iff connection is alive and server is connected
        :rtype bool
        """

        async def heartbeat():
            cmd = "echo {}".format(auth_info.hostname)
            with await self.get_connection(auth_info) as conn_info:
                return await self.execute_ssh(conn_info.connection, cmd)

        try:
            """
            Get connection to hostname ( create if needed) and then attempt
            to run a dummy command. Dummy is needed because sometimes the SSH daemon will open
            a connection but till not have enough resources to to execute incoming commands.
            """
            log_debug("heartbeat {}".format(auth_info.hostname))
            asyncio.run_coroutine_threadsafe(heartbeat(), loop=self.loop).result(timeout=timeout)
            return True
        except Exception:
            return False

    async def get_connection(self, auth_info: AuthInfo) -> AsyncConnInfo:
        """
        Get the connection of the given authentication info

        :param auth_info: AuthInfo, Authentication information object
        :return: AsyncConnInfo, Saved connection
        """
        hostname = auth_info.hostname
        log_debug("Requested connection to {}".format(hostname))
        async with self.coro_conn_locks[hostname]:
            log_debug("\t\t {} Entered lock for {}".format(threading.currentThread().name, hostname))
            """
            A thread level lock is not needed since get_conn can only be called
            by the thread in which the event loop is running.
            A coroutine-level lock is needed because we await on create_connection
            If the lock was not here, then it would be possible for multiple coroutines to
            attempt to create a connection to the same hostname simultaneously.
            coro_conn_locks is a defaultdict but we don't need to worry about thread safety -
            only the thread in which the SSHExec loop is running can access it.
            """
            if (hostname not in self.conn_dict or
                    not self.conn_dict[hostname].client.connected):
                create_conn_params = dict(host=hostname, username=auth_info.username,
                                          password=auth_info.password, port=auth_info.port,
                                          known_hosts=None)
                # create_conn_task = asyncssh.create_connection(SSHClient, **create_conn_params)
                # asyncio.ensure_future(create_conn_task, loop=self.loop)

                conn, conn_client = await asyncssh.create_connection(SSHClient, **create_conn_params)
                access_semaphore = asyncio.Semaphore(value=self.connections_per_host, loop=self.loop)
                self.conn_dict[hostname] = AsyncConnInfo(conn, conn_client, access_semaphore)
                log_debug("\t Created connection to {}".format(hostname))
            log_debug("\t\t exited lock for {}".format(hostname))
        log_debug("Returned cached connection to {}".format(hostname))
        return self.conn_dict[hostname]

    async def async_send_cmd(self, cmd_info: CmdInfo) -> ResultInfo:
        """
        Send the given command asynchronously

        :param cmd_info: Command Info object
        :type cmd_info: CmdInfo
        :return: Result inform ation
        :type: ResultInfo
        """
        conn_info = await self.get_connection(cmd_info)  # type: AsyncConnInfo
        async with conn_info.semaphore:
            return await self.execute_ssh(conn_info.connection, cmd_info.cmd_string, response=cmd_info.response)

    @needs_loop
    def send_cmd(self, cmd: CmdInfo) -> ResultInfo:
        """
        Function to call when sending a command

        :param cmd: str, Command to run
        :return: ResultInfo, Result information
        :raise OSError: Failure in sending the command
        """
        log_debug("Executing {}".format(cmd.cmd_string))
        """
        run_coroutine_threadsafe returns a concurrent.futures.future (not an asyncio.future).
        This means that the calling thread will wait for the result, unlike asyncio.future
        which raises an exception if the result is not yet available.
        Note that async_send_cmd(cmd) does not execute anything yet - it's only
        a coro object and will only be executed when the loop schedules it.
        """

        """
        Event loop batch mode is disabled for this version,
        threadpool is used instead.
        ----
        Place the future in the currently active parallel context,
        do not wait for it to finish
        if self.in_batch_mode:
          self.thread_local.batch_commands[-1].append(FutureInfo(cmd, fut))
          return fut
        else:
        ----
        """
        # if parallel_ssh_allowed_in_context():

        fut = asyncio.run_coroutine_threadsafe(self.async_send_cmd(cmd), loop=self.loop)
        try:
            # If timeout is None, leave it as is. Otherwise, enforce a minimum of <DEFAULT_SSH_TIMEOUT> seconds.
            if cmd.timeout is not None:
                cmd.timeout = max(cmd.timeout, DEFAULT_SSH_TIMEOUT)
            return fut.result(timeout=cmd.timeout)

        except Exception as e:
            # raise builtin TimeoutError instead
            log_debug("{} occured when executing future {}, cancelling it".format(type(e), fut))
            # fut.cancel()
            raise OSError(e)

    async def execute_ssh(self, conn: asyncssh.SSHClientConnection, cmd_string: str,
                          response: str = None) -> ResultInfo:
        """
        The atomic function that runs the given command on the giving connection

        :param conn: Connection to run the command on
        :type conn: asyncssh.SSHClientConnection
        :param cmd_string: Command to run
        :type cmd_string: str
        :param response:
        :return:
        """
        std_output = err_output = None
        log_debug("Executing {}:{}".format(conn._host, cmd_string))
        try:
            stdin, stdout, stderr = await conn.open_session()
            try:
                # skip banner/starting warnings, if exist
                await asyncio.wait_for(stdout.read(), timeout=1, loop=self.loop).result()
            except Exception:
                response = ''
            stdin.write(cmd_string + "\n")
            if ';' in response:
                list_response = response.split(';')
                for response in list_response:
                    if not response:
                        continue
                    stdin.write(response + "\n")
                    stdin.write_eof()
                    std_output = await stdout.readline()
                    # print("response={}, std_output={}".format(response, std_output))
                    err_output = await stderr.readline()
                await stdout.channel.wait_closed()
                await stdin.channel.wait_closed()
                await stderr.channel.wait_closed()
                rc = stdout.channel.get_exit_status()
            else:
                if response:
                    stdin.write(response + "\n")
                stdin.write_eof()
                std_output = await stdout.read()
                err_output = await stderr.read()
                await stdout.channel.wait_closed()
                await stdin.channel.wait_closed()
                await stderr.channel.wait_closed()
                rc = stdout.channel.get_exit_status()

        except Exception as e:
            # Exceptions thrown when failed to connect\send command (usually when server is down or
            # connecting with wrong credentials)
            log_debug(f"Error executing command: {cmd_string}, {type(e)}: {e}")
            raise OSError(e)
        return ResultInfo(stdout=std_output, stderr=err_output, rc=rc, cmd_string=cmd_string)


SSHExec = _SSHExec(debug_flag=False)  # init dispatcher
SSHExec.run_me()
