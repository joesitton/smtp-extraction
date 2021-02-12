@load base/protocols/conn
@load base/protocols/smtp

module SMTPExtraction;

export {
    const path: string = "" &redef;
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    if (code == 220 || cmd == "X-ANONYMOUSTLS" || cmd == "STARTTLS")
    {
        return;
    }

    local md5 = md5_hash(c$id, c$uid);
    local fname = fmt("%s/.SMTP-%s.envelope", path, md5);
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

    close(f);

    if (cmd == "QUIT")
    {
        rename(fname, fmt("%s/SMTP-%s.envelope", path, md5));
    }
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    local fname = fmt("%s/.SMTP-%s.envelope", path, md5_hash(c$id, c$uid));
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

    local fname = fmt("%s/SMTP-%s.data", path, md5_hash(c$id, c$uid));
    local f = open_for_append(fname);

    if (file_size(fname) < 1)
    {
        local timestamp = strftime("%c", network_time());
        write_file(f, fmt("From %s  %s\n", gethostname(), timestamp));
    }

    write_file(f, data + "\n");
    close(f);
}
