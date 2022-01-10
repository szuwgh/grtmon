// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::transmute_ptr_to_ref)]
#![allow(clippy::upper_case_acronyms)]

use libbpf_rs::libbpf_sys;

fn build_skel_config() -> libbpf_rs::Result<libbpf_rs::skeleton::ObjectSkeletonConfig<'static>> {
    let mut builder = libbpf_rs::skeleton::ObjectSkeletonConfigBuilder::new(DATA);
    builder.name("xdppass_bpf").prog("xdp_pass");

    builder.build()
}

#[derive(Default)]
pub struct XdppassSkelBuilder {
    pub obj_builder: libbpf_rs::ObjectBuilder,
}

impl<'a> XdppassSkelBuilder {
    pub fn open(mut self) -> libbpf_rs::Result<OpenXdppassSkel<'a>> {
        let mut skel_config = build_skel_config()?;
        let open_opts = self.obj_builder.opts(std::ptr::null());

        let ret = unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

        Ok(OpenXdppassSkel { obj, skel_config })
    }
}

pub struct OpenXdppassProgs<'a> {
    inner: &'a libbpf_rs::OpenObject,
}

impl<'a> OpenXdppassProgs<'a> {
    pub fn xdp_pass(&self) -> &libbpf_rs::OpenProgram {
        self.inner.prog("xdp_pass").unwrap()
    }
}

pub struct OpenXdppassProgsMut<'a> {
    inner: &'a mut libbpf_rs::OpenObject,
}

impl<'a> OpenXdppassProgsMut<'a> {
    pub fn xdp_pass(&mut self) -> &mut libbpf_rs::OpenProgram {
        self.inner.prog_mut("xdp_pass").unwrap()
    }
}

pub struct OpenXdppassSkel<'a> {
    pub obj: libbpf_rs::OpenObject,
    skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
}

impl<'a> OpenXdppassSkel<'a> {
    pub fn load(mut self) -> libbpf_rs::Result<XdppassSkel<'a>> {
        let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

        Ok(XdppassSkel {
            obj,
            skel_config: self.skel_config,
            links: XdppassLinks::default(),
        })
    }

    pub fn progs(&self) -> OpenXdppassProgs {
        OpenXdppassProgs { inner: &self.obj }
    }

    pub fn progs_mut(&mut self) -> OpenXdppassProgsMut {
        OpenXdppassProgsMut {
            inner: &mut self.obj,
        }
    }
}

pub struct XdppassProgs<'a> {
    inner: &'a libbpf_rs::Object,
}

impl<'a> XdppassProgs<'a> {
    pub fn xdp_pass(&self) -> &libbpf_rs::Program {
        self.inner.prog("xdp_pass").unwrap()
    }
}

pub struct XdppassProgsMut<'a> {
    inner: &'a mut libbpf_rs::Object,
}

impl<'a> XdppassProgsMut<'a> {
    pub fn xdp_pass(&mut self) -> &mut libbpf_rs::Program {
        self.inner.prog_mut("xdp_pass").unwrap()
    }
}

#[derive(Default)]
pub struct XdppassLinks {
    pub xdp_pass: Option<libbpf_rs::Link>,
}

pub struct XdppassSkel<'a> {
    pub obj: libbpf_rs::Object,
    skel_config: libbpf_rs::skeleton::ObjectSkeletonConfig<'a>,
    pub links: XdppassLinks,
}

impl<'a> XdppassSkel<'a> {
    pub fn progs(&self) -> XdppassProgs {
        XdppassProgs { inner: &self.obj }
    }

    pub fn progs_mut(&mut self) -> XdppassProgsMut {
        XdppassProgsMut {
            inner: &mut self.obj,
        }
    }

    pub fn attach(&mut self) -> libbpf_rs::Result<()> {
        let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) };
        if ret != 0 {
            return Err(libbpf_rs::Error::System(-ret));
        }

        self.links = XdppassLinks {
            xdp_pass: (|| {
                let ptr = self.skel_config.prog_link_ptr(0)?;
                if ptr.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(unsafe { libbpf_rs::Link::from_ptr(ptr) }))
                }
            })()?,
        };

        Ok(())
    }
}

const DATA: &[u8] = &[
    127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 64,
    0, 19, 0, 1, 0, 183, 0, 0, 0, 2, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 71, 80, 76, 0, 1, 17, 1,
    37, 14, 19, 5, 3, 14, 16, 23, 27, 14, 17, 1, 18, 6, 0, 0, 2, 52, 0, 3, 14, 73, 19, 63, 25, 58,
    11, 59, 11, 2, 24, 0, 0, 3, 1, 1, 73, 19, 0, 0, 4, 33, 0, 73, 19, 55, 11, 0, 0, 5, 36, 0, 3,
    14, 62, 11, 11, 11, 0, 0, 6, 36, 0, 3, 14, 11, 11, 62, 11, 0, 0, 7, 4, 1, 73, 19, 3, 14, 11,
    11, 58, 11, 59, 5, 0, 0, 8, 40, 0, 3, 14, 28, 15, 0, 0, 9, 15, 0, 0, 0, 10, 22, 0, 73, 19, 3,
    14, 58, 11, 59, 11, 0, 0, 11, 46, 1, 17, 1, 18, 6, 64, 24, 151, 66, 25, 3, 14, 58, 11, 59, 11,
    39, 25, 73, 19, 63, 25, 0, 0, 12, 5, 0, 2, 24, 3, 14, 58, 11, 59, 11, 73, 19, 0, 0, 13, 52, 0,
    3, 14, 58, 11, 59, 11, 73, 19, 0, 0, 14, 15, 0, 73, 19, 0, 0, 15, 19, 1, 3, 14, 11, 11, 58, 11,
    59, 5, 0, 0, 16, 13, 0, 3, 14, 73, 19, 58, 11, 59, 5, 56, 11, 0, 0, 17, 19, 1, 3, 14, 11, 11,
    58, 11, 59, 11, 0, 0, 18, 13, 0, 3, 14, 73, 19, 58, 11, 59, 11, 56, 11, 0, 0, 0, 181, 1, 0, 0,
    4, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 12, 0, 36, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 16, 0, 0, 0, 2, 80, 0, 0, 0, 63, 0, 0, 0, 1, 28, 9, 3, 0, 0, 0, 0, 0, 0, 0, 0, 3, 75,
    0, 0, 0, 4, 82, 0, 0, 0, 4, 0, 5, 90, 0, 0, 0, 6, 1, 6, 95, 0, 0, 0, 8, 7, 7, 133, 0, 0, 0,
    178, 0, 0, 0, 4, 2, 152, 20, 8, 128, 0, 0, 0, 0, 8, 140, 0, 0, 0, 1, 8, 149, 0, 0, 0, 2, 8,
    158, 0, 0, 0, 3, 8, 165, 0, 0, 0, 4, 0, 5, 115, 0, 0, 0, 7, 4, 9, 5, 189, 0, 0, 0, 5, 8, 10,
    159, 0, 0, 0, 213, 0, 0, 0, 3, 40, 5, 198, 0, 0, 0, 7, 2, 11, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0,
    0, 1, 90, 224, 0, 0, 0, 1, 6, 238, 0, 0, 0, 12, 1, 81, 237, 0, 0, 0, 1, 6, 245, 0, 0, 0, 13,
    252, 0, 0, 0, 1, 10, 140, 0, 0, 0, 13, 241, 0, 0, 0, 1, 9, 140, 0, 0, 0, 13, 68, 1, 0, 0, 1,
    11, 93, 1, 0, 0, 0, 5, 233, 0, 0, 0, 5, 4, 14, 250, 0, 0, 0, 15, 61, 1, 0, 0, 24, 2, 163, 20,
    16, 241, 0, 0, 0, 82, 1, 0, 0, 2, 164, 20, 0, 16, 252, 0, 0, 0, 82, 1, 0, 0, 2, 165, 20, 4, 16,
    5, 1, 0, 0, 82, 1, 0, 0, 2, 166, 20, 8, 16, 15, 1, 0, 0, 82, 1, 0, 0, 2, 168, 20, 12, 16, 31,
    1, 0, 0, 82, 1, 0, 0, 2, 169, 20, 16, 16, 46, 1, 0, 0, 82, 1, 0, 0, 2, 171, 20, 20, 0, 10, 133,
    0, 0, 0, 246, 0, 0, 0, 4, 27, 14, 98, 1, 0, 0, 17, 123, 1, 0, 0, 14, 5, 165, 18, 72, 1, 0, 0,
    143, 1, 0, 0, 5, 166, 0, 18, 93, 1, 0, 0, 143, 1, 0, 0, 5, 167, 6, 18, 102, 1, 0, 0, 162, 1, 0,
    0, 5, 168, 12, 0, 3, 155, 1, 0, 0, 4, 82, 0, 0, 0, 6, 0, 5, 79, 1, 0, 0, 8, 1, 10, 173, 1, 0,
    0, 116, 1, 0, 0, 6, 25, 10, 159, 0, 0, 0, 110, 1, 0, 0, 4, 24, 0, 85, 98, 117, 110, 116, 117,
    32, 99, 108, 97, 110, 103, 32, 118, 101, 114, 115, 105, 111, 110, 32, 49, 50, 46, 48, 46, 49,
    45, 56, 98, 117, 105, 108, 100, 49, 0, 115, 114, 99, 47, 98, 112, 102, 47, 120, 100, 112, 112,
    97, 115, 115, 46, 98, 112, 102, 46, 99, 0, 47, 111, 112, 116, 47, 114, 115, 112, 114, 111, 106,
    101, 99, 116, 47, 118, 105, 108, 108, 117, 115, 0, 95, 95, 108, 105, 99, 101, 110, 115, 101, 0,
    99, 104, 97, 114, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95,
    95, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 0, 88, 68, 80, 95, 65, 66,
    79, 82, 84, 69, 68, 0, 88, 68, 80, 95, 68, 82, 79, 80, 0, 88, 68, 80, 95, 80, 65, 83, 83, 0,
    88, 68, 80, 95, 84, 88, 0, 88, 68, 80, 95, 82, 69, 68, 73, 82, 69, 67, 84, 0, 120, 100, 112,
    95, 97, 99, 116, 105, 111, 110, 0, 108, 111, 110, 103, 32, 105, 110, 116, 0, 117, 110, 115,
    105, 103, 110, 101, 100, 32, 115, 104, 111, 114, 116, 0, 95, 95, 117, 105, 110, 116, 49, 54,
    95, 116, 0, 120, 100, 112, 95, 112, 97, 115, 115, 0, 105, 110, 116, 0, 99, 116, 120, 0, 100,
    97, 116, 97, 0, 95, 95, 117, 51, 50, 0, 100, 97, 116, 97, 95, 101, 110, 100, 0, 100, 97, 116,
    97, 95, 109, 101, 116, 97, 0, 105, 110, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100,
    101, 120, 0, 114, 120, 95, 113, 117, 101, 117, 101, 95, 105, 110, 100, 101, 120, 0, 101, 103,
    114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 120, 100, 112, 95, 109, 100, 0,
    101, 116, 104, 0, 104, 95, 100, 101, 115, 116, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32,
    99, 104, 97, 114, 0, 104, 95, 115, 111, 117, 114, 99, 101, 0, 104, 95, 112, 114, 111, 116, 111,
    0, 95, 95, 117, 49, 54, 0, 95, 95, 98, 101, 49, 54, 0, 101, 116, 104, 104, 100, 114, 0, 159,
    235, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 12, 1, 0, 0, 12, 1, 0, 0, 209, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 2, 2, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 4, 24, 0, 0, 0, 8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 13,
    0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 22, 0, 0, 0, 3, 0, 0, 0, 64, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0,
    0, 96, 0, 0, 0, 48, 0, 0, 0, 3, 0, 0, 0, 128, 0, 0, 0, 63, 0, 0, 0, 3, 0, 0, 0, 160, 0, 0, 0,
    78, 0, 0, 0, 0, 0, 0, 8, 4, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 13, 6, 0, 0, 0, 97, 0, 0, 0, 1, 0, 0, 0, 101, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32,
    0, 0, 1, 105, 0, 0, 0, 1, 0, 0, 12, 5, 0, 0, 0, 166, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 8, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 171, 0, 0, 0, 0, 0,
    0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 191, 0, 0, 0, 0, 0, 0, 14, 9, 0, 0, 0, 1, 0, 0, 0, 201, 0, 0, 0,
    1, 0, 0, 15, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 120, 100, 112, 95, 109, 100,
    0, 100, 97, 116, 97, 0, 100, 97, 116, 97, 95, 101, 110, 100, 0, 100, 97, 116, 97, 95, 109, 101,
    116, 97, 0, 105, 110, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 114,
    120, 95, 113, 117, 101, 117, 101, 95, 105, 110, 100, 101, 120, 0, 101, 103, 114, 101, 115, 115,
    95, 105, 102, 105, 110, 100, 101, 120, 0, 95, 95, 117, 51, 50, 0, 117, 110, 115, 105, 103, 110,
    101, 100, 32, 105, 110, 116, 0, 99, 116, 120, 0, 105, 110, 116, 0, 120, 100, 112, 95, 112, 97,
    115, 115, 0, 120, 100, 112, 0, 47, 111, 112, 116, 47, 114, 115, 112, 114, 111, 106, 101, 99,
    116, 47, 118, 105, 108, 108, 117, 115, 47, 46, 47, 115, 114, 99, 47, 98, 112, 102, 47, 120,
    100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46, 99, 0, 125, 0, 99, 104, 97, 114, 0, 95, 95,
    65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95, 95, 0, 95, 95, 108, 105, 99,
    101, 110, 115, 101, 0, 108, 105, 99, 101, 110, 115, 101, 0, 159, 235, 1, 0, 32, 0, 0, 0, 0, 0,
    0, 0, 20, 0, 0, 0, 20, 0, 0, 0, 28, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 114, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 16, 0, 0, 0, 114, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 118, 0,
    0, 0, 164, 0, 0, 0, 1, 104, 0, 0, 0, 0, 12, 0, 0, 0, 255, 255, 255, 255, 4, 0, 8, 0, 8, 124,
    11, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 197, 0, 0, 0,
    4, 0, 168, 0, 0, 0, 8, 1, 1, 251, 14, 13, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 46, 47, 115, 114,
    99, 47, 98, 112, 102, 0, 47, 117, 115, 114, 47, 105, 110, 99, 108, 117, 100, 101, 47, 108, 105,
    110, 117, 120, 0, 47, 117, 115, 114, 47, 105, 110, 99, 108, 117, 100, 101, 47, 98, 105, 116,
    115, 0, 47, 117, 115, 114, 47, 105, 110, 99, 108, 117, 100, 101, 47, 97, 115, 109, 45, 103,
    101, 110, 101, 114, 105, 99, 0, 0, 120, 100, 112, 112, 97, 115, 115, 46, 98, 112, 102, 46, 99,
    0, 1, 0, 0, 98, 112, 102, 46, 104, 0, 2, 0, 0, 116, 121, 112, 101, 115, 46, 104, 0, 3, 0, 0,
    105, 110, 116, 45, 108, 108, 54, 52, 46, 104, 0, 4, 0, 0, 105, 102, 95, 101, 116, 104, 101,
    114, 46, 104, 0, 2, 0, 0, 116, 121, 112, 101, 115, 46, 104, 0, 2, 0, 0, 0, 0, 9, 2, 0, 0, 0, 0,
    0, 0, 0, 0, 24, 5, 1, 10, 3, 19, 1, 2, 2, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 13, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 88, 0, 0, 0, 17, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 34, 0, 0,
    0, 18, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 10, 0,
    0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0,
    10, 0, 0, 0, 4, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 6, 0, 0, 0, 26, 0, 0, 0, 0, 0,
    0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 43, 0, 0, 0, 0,
    0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 55, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 76, 0, 0, 0,
    0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 83, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 94, 0,
    0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 103, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0,
    109, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 115, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0,
    0, 0, 121, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0,
    4, 0, 0, 0, 134, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 142, 0, 0, 0, 0, 0, 0, 0, 10, 0,
    0, 0, 4, 0, 0, 0, 153, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0,
    10, 0, 0, 0, 4, 0, 0, 0, 167, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 181, 0, 0, 0, 0, 0,
    0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 194, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 205, 0, 0, 0,
    0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 216, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 227, 0,
    0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 239, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0,
    251, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0,
    0, 0, 17, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 30, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0,
    4, 0, 0, 0, 43, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 56, 1, 0, 0, 0, 0, 0, 0, 10, 0,
    0, 0, 4, 0, 0, 0, 69, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 87, 1, 0, 0, 0, 0, 0, 0,
    10, 0, 0, 0, 4, 0, 0, 0, 99, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 107, 1, 0, 0, 0, 0,
    0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 119, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 131, 1, 0, 0,
    0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 156, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 167, 1,
    0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0, 178, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 0, 0, 0,
    28, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
    0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 5, 0,
    0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 181, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2,
    0, 0, 0, 8, 7, 0, 46, 100, 101, 98, 117, 103, 95, 97, 98, 98, 114, 101, 118, 0, 46, 116, 101,
    120, 116, 0, 46, 114, 101, 108, 46, 66, 84, 70, 46, 101, 120, 116, 0, 120, 100, 112, 95, 112,
    97, 115, 115, 0, 46, 100, 101, 98, 117, 103, 95, 115, 116, 114, 0, 120, 100, 112, 0, 46, 114,
    101, 108, 46, 100, 101, 98, 117, 103, 95, 105, 110, 102, 111, 0, 46, 108, 108, 118, 109, 95,
    97, 100, 100, 114, 115, 105, 103, 0, 95, 95, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 101,
    108, 46, 100, 101, 98, 117, 103, 95, 108, 105, 110, 101, 0, 46, 114, 101, 108, 46, 100, 101,
    98, 117, 103, 95, 102, 114, 97, 109, 101, 0, 120, 100, 112, 112, 97, 115, 115, 46, 98, 112,
    102, 46, 99, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97, 98, 0, 46, 114,
    101, 108, 46, 66, 84, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 145, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 146, 11, 0, 0, 0, 0, 0, 0, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 90, 0, 0, 0, 1, 0, 0, 0, 3, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 1, 0, 0, 0, 0, 0, 0, 185, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 9,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 8, 0, 0, 0, 0, 0, 0, 160, 2, 0,
    0, 0, 0, 0, 0, 18, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 43, 0,
    0, 0, 1, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 247, 2, 0, 0, 0, 0, 0, 0,
    130, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 165, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 121, 4, 0, 0, 0,
    0, 0, 0, 245, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 161, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 11,
    0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 9, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16,
    0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    110, 6, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 64, 11, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 11, 0, 0, 0, 8, 0, 0, 0,
    0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 118, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 192, 6, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 96, 11, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 13, 0, 0,
    0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 6, 0, 0, 0, 0, 0, 0, 201, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 11, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 18,
    0, 0, 0, 15, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 74, 0, 0, 0, 3, 76, 255,
    111, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 11, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
    0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 153, 0, 0,
    0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 184, 7, 0, 0, 0, 0, 0, 0, 216,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0,
];
