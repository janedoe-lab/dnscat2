##
# controller.rb
# Created April, 2014
# By Ron Bowes
#
# See: LICENSE.md
#
# This keeps track of all sessions.
##

require 'controller/controller_commands'
require 'controller/packet'
require 'controller/session'
require 'libs/commander'
require 'libs/dnscat_exception'

require 'trollop'

class Controller
  include ControllerCommands

  attr_accessor :window

  def initialize()
    @commander = Commander.new()
    @sessions = {}

    _register_commands()

    WINDOW.on_input() do |data|
      data = Settings::GLOBAL.do_replace(data)
      begin
        @commander.feed(data)
      rescue ArgumentError => e
        WINDOW.puts("Error: #{e}")
        WINDOW.puts()
        @commander.educate(data, WINDOW)
      end
    end
  end

  def _get_or_create_session(id, source)
    if(@sessions[id])
      return @sessions[id]
    end

    return (@sessions[id] = Session.new(id, WINDOW, source))
  end

  def session_exists?(id)
    return !@sessions[id].nil?
  end

  def find_session(id)
    return @sessions[id]
  end

  def find_session_by_window(id)
    id = id.to_s()
    @sessions.each_value do |session|
      if(session.window.id.to_s() == id)
        return session
      end
    end

    return nil
  end

  def kill_session(id)
    session = find(id)

    if(!session.nil?)
      session.kill()
    end
  end

  def list()
    return @sessions
  end

  def feed(data, max_length, source, question)
    # If it's a ping packet, handle it up here
    if(Packet.peek_type(data) == Packet::MESSAGE_TYPE_PING)
      WINDOW.puts("Responding to ping packet: #{Packet.parse(data).body}")
      return data
    end

    packet_type = Packet.peek_type(data)

    if(!Packet.valid_type(data))
      raise(DnscatException, "Unknown message type: 0x%x" % packet_type)
    end

    session_id = Packet.peek_session_id(data)

    if !@sessions[session_id] && !(packet_type == Packet::MESSAGE_TYPE_SYN || packet_type == Packet::MESSAGE_TYPE_ENC)
      raise(DnscatException, "Received packet for unknown session #{session_id}, packet type #{packet_type}")
    end

    session = _get_or_create_session(session_id, source)

    if session.state == Session::STATE_KILLED
      raise(DnscatException, "Received packet for killed session #{session_id}")
    end

    if session.state != Session::STATE_ESTABLISHED && packet_type == Packet::MESSAGE_TYPE_MSG
      raise(DnscatException, "Received message packet for non-established session #{session_id}")
    end

    return session.feed(data, max_length, source, question)
  end
end
