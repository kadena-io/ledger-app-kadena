use nanos_sdk::Pic;
use nanos_sdk::nvm::*;
// use bitflags::bitflags;

// TODO: use bitflags, and better types for Settings
// bitflags! {
//     pub struct Flags: u32 {
//         const HashSigning = 0b00000001;
//     }
// }

// #[derive(PartialEq, Debug)]
// enum HashSigningSettings {
//     HashSigningSettingsDisabled,
//     HashSigningSettingsEnabled
// }

// This is necessary to store the object in NVM and not in RAM
#[link_section=".nvm_data"]
static mut SETTINGS: Pic<AtomicStorage<u8>> =
    Pic::new(AtomicStorage::new(&0));

// In the program, `SETTINGS` must not be used directly. It is a static variable
// and using it would require unsafe everytime. Instead, a reference must be
// taken, so the borrow checker will be able to do its job correctly. This is
// crucial: the memory location of the stored object may be moved due to
// atomicity implementation, and the borrow checker should prevent any use of
// old references to a value which has been updated and moved elsewhere.
//
// Furthermore, since the data is stored in Code space, it is relocated during
// application installation. Therefore the address to this data must be
// translated: this is enforced by the [`Pic`](crate::Pic) wrapper.
//


pub struct Settings;

impl Settings {
    pub fn new() -> Settings { Settings}

    #[inline(never)]
    pub fn get(&self) -> u8 {
        let settings = unsafe { SETTINGS.get_mut() };
        return *settings.get_ref();
    }

    // The inline(never) is important. Otherwise weird segmentation faults happen on speculos.
    #[inline(never)]
    pub fn set(&mut self, v: &u8) {
        let settings = unsafe { SETTINGS.get_mut() };
        settings.update(&v);
    }
}
