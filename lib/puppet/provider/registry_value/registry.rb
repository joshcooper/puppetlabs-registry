require 'puppet/type'
Puppet::Type.type(:registry_value).provide(:registry) do
  require 'pathname' # JJM WORK_AROUND #14073
  require Pathname.new(__FILE__).dirname.dirname.dirname.expand_path + 'modules/registry/registry_base'
  include Puppet::Modules::Registry::RegistryBase

  defaultfor :operatingsystem => :windows
  confine    :operatingsystem => :windows

  def self.instances
    []
  end

  def create
    Puppet.info("creating: #{self}")

    valuepath.with_key_loaded do
      valuepath.hkey.open(valuepath.subkey, Win32::Registry::KEY_ALL_ACCESS | valuepath.access) do |reg|
        ary = to_native(resource[:type], resource[:data])
        reg.write(valuepath.valuename, ary[0], ary[1])
      end
    end
  end

  def exists?
    Puppet.info("exists: #{self}")

    found = false
    valuepath.with_key_loaded do
      valuepath.hkey.open(valuepath.subkey, Win32::Registry::KEY_READ | valuepath.access) do |reg|
        type = [0].pack('L')
        size = [0].pack('L')
        found = reg_query_value_ex_a.call(reg.hkey, valuepath.valuename, 0, type, 0, size) == 0
      end
    end
    found
  end

  def flush
    return if resource[:ensure] == :absent

    Puppet.info("flushing: #{self}")

    valuepath.with_key_loaded do
      valuepath.hkey.open(valuepath.subkey, Win32::Registry::KEY_ALL_ACCESS | valuepath.access) do |reg|
        ary = to_native(regvalue[:type], regvalue[:data])
        reg.write(valuepath.valuename, ary[0], ary[1])
      end
    end
  end

  def destroy
    Puppet.info("destroying: #{self}")

    valuepath.with_key_loaded do
      valuepath.hkey.open(valuepath.subkey, Win32::Registry::KEY_ALL_ACCESS | valuepath.access) do |reg|
        reg.delete_value(valuepath.valuename)
      end
    end
  end

  def type
    regvalue[:type] || :absent
  end

  def type=(value)
    regvalue[:type] = value
  end

  def data
    regvalue[:data] || :absent
  end

  def data=(value)
    regvalue[:data] = value
  end

  def regvalue
    unless @regvalue
      @regvalue = {}
      valuepath.with_key_loaded do
        valuepath.hkey.open(valuepath.subkey, Win32::Registry::KEY_ALL_ACCESS | valuepath.access) do |reg|
          type = [0].pack('L')
          size = [0].pack('L')

          if reg_query_value_ex_a.call(reg.hkey, valuepath.valuename, 0, type, 0, size) == 0
            @regvalue[:type], @regvalue[:data] = from_native(reg.read(valuepath.valuename))
          end
        end
      end
    end
    @regvalue
  end

  def valuepath
    @valuepath ||= resource.parameter(:path)
  end

  # convert puppet type and data to native
  def to_native(ptype, pdata)
    ndata =
      case ptype
      when :binary
        pdata.scan(/[a-f\d]{2}/i).map{ |byte| [byte].pack('H2') }.join('')
      else
        pdata
      end

    return [name2type(ptype), ndata]
  end

  # convert from native type and data to puppet
  def from_native(ary)
    ntype, ndata = ary

    pdata =
      case type2name(ntype)
      when :binary
        ndata.scan(/./).map{ |byte| byte.unpack('H2')[0]}.join(' ')
      else
        ndata
      end

    return [type2name(ntype), pdata]
  end

  def reg_query_value_ex_a
    @@reg_query_value_ex_a ||= Win32API.new('advapi32', 'RegQueryValueEx', 'LPLPPP', 'L')
  end

  # def to_s
  #   "#{valuepath.hkey.keyname}\\#{valuepath.subkey}\\#{valuepath.valuename}"
  # end
end
