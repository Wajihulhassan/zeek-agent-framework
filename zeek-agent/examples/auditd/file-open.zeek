##! Logs socket events activity

@load zeek-agent

module Agent_FileOpen;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:             time   &log;
		host_ts:        time   &log;
		host:           string &log;
		hostname:       string &log;
		action:         string &log;
		pid:            int    &log;
		success:        int    &log;
		path:        string    &log;
		file_path:        string    &log;
		inode:        int    &log;
	};
}

event Agent_FileOpen::file_open(result: ZeekAgent::Result,
                                    action: string, pid: int,
                                    host_time: int, success: int,
				    path: string, file_path: string, inode: int)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	local host_ts = double_to_time(host_time);
	local info = Info($ts = network_time(),
	                  $host_ts = host_ts,
	                  $host = result$host,
	                  $hostname = ZeekAgent::getHostInfo(result$host)$hostname,
	                  $pid = pid,
	                  $action = action,
	                  $success = success,
			  $path = path,
			  $file_path = file_path,
			  $inode = inode);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-file_opening"]);

	local query = ZeekAgent::Query($ev=Agent_FileOpen::file_open,
	                                $query="SELECT action, pid, time, success, path, file_path, inode FROM file_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
