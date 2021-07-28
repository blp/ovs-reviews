use ::std::ffi;
use ::std::ptr;
use ::std::os::raw;
use ::libc;

#[repr(C)] // from ovs/include/openvswitch/hmap.h
pub struct hmap_node_c {
    hash: libc::size_t,
    next: *mut hmap_node_c
}

#[repr(C)] // from ovs/include/openvswitch/hmap.h
pub struct hmap_c {
    buckets: *mut *mut hmap_node_c,
    one: *mut hmap_node_c,
    mask: libc::size_t,
    n: libc::size_t
}

#[repr(C)] // from ovs/lib/sset.h
pub struct sset_c {
    map: hmap_c
}

mod ovn_c {
    use ::std::os::raw;
    use super::sset_c;

    #[link(name = "ovn")]
    extern "C" {
        // from lib/expr.c
        pub fn expr_references_from_string(s: *const raw::c_char,addr_sets: *mut sset_c, port_groups: *mut sset_c);
        pub fn sset_first(s: *const sset_c) -> *const raw::c_char;
        pub fn sset_next(s: *const sset_c, name: *const raw::c_char) -> *const raw::c_char;
    }

}
    
// Wrapper around OVS function expr_references_from_string, that parses the match string and returns
// sets of address_sets and port_groups
pub fn expr_references(__match : &String) -> ddlog_std::tuple2<ddlog_std::Set<String>, ddlog_std::Set<String>> {
    let mut res_as: ddlog_std::Set<String> = ddlog_std::Set::new();
    let mut res_pg: ddlog_std::Set<String> = ddlog_std::Set::new();
    unsafe {
        let mut x = hmap_c {
            buckets: ptr::null_mut(),
            one: ptr::null_mut(),
            mask: 0 as libc::size_t,
            n: 0 as libc::size_t
        };
        x.buckets = &mut x.one;
        let mut addr_sets = sset_c {
            map: x
        };

        let mut pg = hmap_c {
            buckets: ptr::null_mut(),
            one: ptr::null_mut(),
            mask: 0 as libc::size_t,
            n: 0 as libc::size_t
        };
        pg.buckets = &mut pg.one;
        let mut port_groups = sset_c {
            map: pg
        };
        ovn_c::expr_references_from_string(ffi::CString::new(__match.as_str()).unwrap().as_ptr(), &mut addr_sets as *mut sset_c, &mut port_groups as *mut sset_c);

        // Now go through addr_sets and add to res_as
        let mut ptr = ovn_c::sset_first(&addr_sets);
        while (ptr != ptr::null()) {
            res_as.insert(ffi::CStr::from_ptr(ptr).to_owned().into_string().unwrap());

            ptr = ovn_c::sset_next(&addr_sets, ptr);
        }
        // Now go through port_groups and add to res_pg
        ptr = ovn_c::sset_first(&port_groups);
        while (ptr != ptr::null()) {
            res_pg.insert(ffi::CStr::from_ptr(ptr).to_owned().into_string().unwrap());

            ptr = ovn_c::sset_next(&port_groups, ptr);
        }
    }
    ddlog_std::tuple2(res_as, res_pg)
}
