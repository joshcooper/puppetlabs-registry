module Puppet::Modules::Registry::UserProfile
  # REMIND: only load this on Windows
  require 'puppet/util/windows/security'
  include Puppet::Util::Windows::Security

  RegLoadKey = Win32API.new('advapi32', 'RegLoadKey', 'LPP', 'L')
  RegUnLoadKey = Win32API.new('advapi32', 'RegUnLoadKey', 'LP', 'L')

  def loaded?(sid)
    # Always disable redirection here
    !!Win32::Registry::HKEY_USERS.open(sid, Win32::Registry::KEY_READ | 0x100) {|reg| true } rescue false
  end

  # Evaluate the block with the user's profile loaded
  def with_user_profile(sid, &block)
    # no-op if it's already loaded
    return yield if loaded?(sid)

    # get profile path for sid
    path = profile_path(sid)

    # elevate privileges
    with_privilege(SE_RESTORE_NAME) do
      with_privilege(SE_BACKUP_NAME) do
        # load the hive from path
        if RegLoadKey.call(Win32::Registry::HKEY_USERS.hkey, sid, path) != 0
          raise "Failed to load user profile: #{sid}"
        end
        begin
          yield
        ensure
          RegUnLoadKey.call(Win32::Registry::HKEY_USERS.hkey, sid)
        end
      end
    end
  end

  # get the path to the user's profile on disk
  def profile_path(sid)
    Win32::Registry::HKEY_LOCAL_MACHINE.open("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{sid}", Win32::Registry::KEY_READ | 0x100) do |reg|
      # expand any environment variables if present
      dir = reg.read_s_expand('ProfileImagePath')
      raise "ProfileImagePath not specified for SID #{sid}" unless dir

      dat = "#{dir}\\ntuser.dat"

      unless File.exists?(dat)
        if dat =~ /system32/
          # system profiles, e.g. S-1-5-18, reside in the %windir%\system32 directory,
          # but we are a 32-bit process, and windows will redirect us, unless we
          # explicitly refer to sysnative
          dat.sub!(/system32/, 'sysnative')
        else
          raise "User has never interactively logged in: #{dat}"
        end
      end

      raise "User's profile does not exist: #{dat}" unless File.exists?(dat)

      dat
    end
  end
end
