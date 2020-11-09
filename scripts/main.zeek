@load base/protocols/conn
@load base/protocols/smtp

module SMTPExtraction;

export {
    const path: string = "" &redef;
}

event smtp_data(c: connection, is_orig: bool, data: string)
{
    if (c$smtp$tls == T)
    {
        skip_smtp_data(c);
        return;
    }

    local fname = generate_extraction_filename(path, c, fmt("%s_.data", c$uid));

    if (file_size(fname) < 1)
    {
        local o = open(fname);
        write_file(o, "From nobody  Thu Jan 1 00:00:00 1970\n");
        close(o);
    }

    local a = open_for_append(fname);
    write_file(a, data + "\n");
    close(a);
}
