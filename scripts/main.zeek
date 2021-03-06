@load base/protocols/conn
@load base/protocols/smtp

module SMTPExtraction;

export {
    const path: string = "" &redef;
}

event zeek_init()
{
    local paths = split_string(path, /\//);
    local current = "";

    for (p in paths)
    {
       current = fmt("%s/%s", current, paths[p]);
       mkdir(current);
    }
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    if (code == 220 || cmd == "X-ANONYMOUSTLS" || cmd == "STARTTLS")
    {
        return;
    }

    local sha256 = sha256_hash(c$id, c$uid);
    local fname = fmt("%s/.SMTP-%s.envelope", path, sha256);
    local f = open_for_append(fname);

    if (cmd == "(UNKNOWN)")
    {
        cmd = "";
    }

    if (msg == "(UNKNOWN)")
    {
        msg = "";
    }

    if (cont_resp == F)
    {
        write_file(f, fmt("%s%s%s%s%s\n", code, cmd == "" ? "" : " ", cmd, msg == "" ? "" : " ", msg));
    }
    else
    {
        write_file(f, fmt("%s%s%s\n", code, msg == "" ? "" : " ", msg));
    }

    if (cmd == "QUIT")
    {
        rename(fmt("%s/.SMTP-%s.mbox", path, sha256), fmt("%s/SMTP-%s.mbox", path, sha256));
        rename(fname, fmt("%s/SMTP-%s.envelope", path, sha256));
    }

    close(f);
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    local fname = fmt("%s/.SMTP-%s.envelope", path, sha256_hash(c$id, c$uid));
    local f = open_for_append(fname);

    if (c$smtp$tls == T || command == "X-ANONYMOUSTLS" || command == "STARTTLS")
    {
        unlink(fname);
        return;
    }

    if (command == "(UNKNOWN)")
    {
        command = "";
    }

    if (arg == "(UNKNOWN)")
    {
        arg = "";
    }

    write_file(f, fmt("%s%s%s\n", command, arg == "" ? "" : " ", arg));
    close(f);
}

event smtp_data(c: connection, is_orig: bool, data: string)
{
    if (c$smtp$tls == T)
    {
        skip_smtp_data(c);
        return;
    }

    local fname = fmt("%s/.SMTP-%s.mbox", path, sha256_hash(c$id, c$uid));
    local f = open_for_append(fname);

    if (file_size(fname) < 1)
    {
        local timestamp = strftime("%c", network_time());
        write_file(f, fmt("From %s  %s\n", gethostname(), timestamp));
    }

    write_file(f, data + "\n");
    close(f);
}
