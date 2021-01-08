@load base/protocols/conn
@load base/protocols/smtp

module SMTPExtraction;

export {
    const path: string = "" &redef;
}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid:count)
{
	if ( atype == Analyzer::ANALYZER_SMTP )
	{
	local both_file = generate_extraction_filename(path, c, fmt("%s_%s", c$uid, ".raw"));
        local f = open(both_file);
        set_contents_file(c$id, CONTENTS_BOTH,f);
	}
}
