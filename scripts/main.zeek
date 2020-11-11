@load base/protocols/conn
@load base/protocols/smtp

module SMTPExtraction;

export {
    const path: string = "" &redef;
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
    local fname = fmt("SMTP-%s.envelope", c$uid);
    local p = fmt("%s.envelopes/%s", path, fname);
    local f = open_for_append(p);

    if (code == 220)
    {
        return;
    }

    if (c$smtp$tls == T)
    {
        unlink(p);
        return;
    }

    if (cont_resp == F)
    {
        write_file(f, fmt("%s %s %s\n", code, cmd, msg));
    }
    else
    {
        write_file(f, fmt("%s %s\n", code, msg));
    }

    close(f);

    if (cmd == "QUIT")
    {
        rename(p, fmt("%s%s", path, fname));
    }
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
    local fname = fmt("%s.envelopes/SMTP-%s.envelope", path, c$uid);
    local f = open_for_append(fname);

    write_file(f, fmt("%s %s\n", command, arg));
    close(f);
}

event smtp_data(c: connection, is_orig: bool, data: string)
{
    if (c$smtp$tls == T)
    {
        skip_smtp_data(c);
        return;
    }

    local fname = fmt("%s/SMTP-%s.data", path, c$uid);
    local f = open_for_append(fname);

    if (file_size(fname) < 1)
    {
        local timestamp = strftime("%c", network_time());
        write_file(f, fmt("From %s  %s\n", gethostname(), timestamp));
    }

    write_file(f, data + "\n");
    close(f);
}
