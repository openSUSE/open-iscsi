# meson build file for etc

subdir('systemd')

# for our interface example file
iscsi_etc_iface_file_src = files('iface.example')

# for our config file
iscsi_etc_config_file_src = files('iscsid.conf')

# templated etc files
iscsi_etc_files_arr = {}
if install_dbdir_move_readme
  iscsi_etc_files = ['README.DB-files-moved']
  iscsi_etc_files_arr = {}
  foreach u: iscsi_etc_files
    iscsi_etc_files_arr += {u: files(u + '.template')}
  endforeach
endif
