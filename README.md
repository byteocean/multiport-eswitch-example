# A packet forwarding example for the multiport eswitch mode on Mellanox ConnectX-6 Dx SmartNIC
1. Following the [instructions](https://doc.dpdk.org/guides/nics/mlx5.html#multiport-e-switch) to enable multiport eswitch mode
2. Install DPDK 23.11
3. Copy the files in this directory to the DPDK source code directory for examples (e.g., /examples/multiport_eswitch)
4. Make small change and add repo name to `/examples/meson.build` and run command `meson configure -Dexamples=repo_name`
5. Compile the example
6. Run the application with `sudo ./multiport_eswitch -l 0,1 -n 2 -r 2 -a 3b:00.0,dv_flow_en=2,dv_esw_en=1,fdb_def_rule_en=1,representor=pf0-1vf0 --vdev=virtio_user0,path=/dev/vhost-net,queue_size=1024,mac=fa:e4:cf:2d:11:b9`


