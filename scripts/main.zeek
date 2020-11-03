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
    local f = open_for_append(fname);
    write_file(f, data + "\n");
    close(f);
}
