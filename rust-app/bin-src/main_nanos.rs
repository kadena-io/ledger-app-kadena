use kadena::implementation::*;
use kadena::interface::*;
use kadena::settings::*;
use ledger_parser_combinators::interp_parser::set_from_thunk;

use nanos_sdk::io;
use nanos_sdk::buttons::{ButtonEvent};
use nanos_ui::ui::{SingleMessage};

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

use ledger_parser_combinators::interp_parser::OOB;
use kadena::*;

// Pulling this out of sample_main to global const saves 24 bytes
// But the SingleMessage::new fails to work with global const, therefore doing fill_idle_menu
const IDLE_MENU: [&str; 3] = [ concat!("Kadena ", env!("CARGO_PKG_VERSION")), "Blind Signing", "Quit" ];
fn fill_idle_menu(arr: &mut [&str; 3]) {
    for (i, s) in IDLE_MENU.iter().enumerate() {
        arr[i] = s;
    }
}

#[cfg(not(test))]
#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    let mut states = ParsersState::NoState;
    let mut menu = Menu::new(&IDLE_MENU);

    info!("Kadena app {}", env!("CARGO_PKG_VERSION"));

    loop {
        // Draw some 'welcome' screen
        match states {
            ParsersState::NoState => {
                // Using IDLE_MENU here does not work, therefore using this to avoid duplication
                let mut arr: [&str; 3] = ["", "", ""];
                fill_idle_menu(&mut arr);
                menu.show(&arr);
            },
            ParsersState::SettingsState(0) => {
                // Using arr is important here. `menu.show(&[ ... ])` doesn't work
                let arr = [ "Enable Blind Signing", "Back" ];
                menu.show(&arr);
            },
            ParsersState::SettingsState(1) => {
                let arr = [ "Disable Blind Signing", "Back" ];
                menu.show(&arr);
            },
            _ => {
                let arr = [ "Working...", "Cancel" ];
                menu.show(&arr);
            },
        }

        info!("Fetching next event.");
        // Wait for either a specific button push to exit the app
        // or an APDU command
        match comm.next_event() {
            io::Event::Command(ins) => {
                menu.reset();
                match handle_apdu(&mut comm, ins, &mut states) {
                    Ok(()) => comm.reply_ok(),
                    Err(sw) => comm.reply(sw),
                }
            } ,
            io::Event::Button(btn) => match menu.update(btn) {
                Some(0) => match states {
                    ParsersState::SettingsState(v) => { let new = match v { 0 => 1, _ => 0}; set_settings(&new); states = ParsersState::SettingsState(new); },
                    _ => (),
                }
                Some(1) => match states {
                    ParsersState::SettingsState(_) => { menu.reset(); states = ParsersState::NoState; },
                    ParsersState::NoState => { menu.reset(); states = ParsersState::SettingsState(get_current_settings()); },
                    _ => { info!("Resetting at user direction via busy menu"); menu.reset(); set_from_thunk(&mut states, || ParsersState::NoState); }
                }
                Some(2) => { info!("Exiting app at user direction via root menu"); nanos_sdk::exit_app(0) },
                _ => (),
            },
            io::Event::Ticker => {
                trace!("Ignoring ticker event");
            },
        }

        // info!("Event handled.");
    }
}

#[repr(u8)]
#[derive(Debug)]
enum Ins {
    GetVersion,
    GetPubkey,
    Sign,
    SignHash,
    GetVersionStr,
    Exit
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            0 => Ins::GetVersion,
            2 => Ins::GetPubkey,
            3 => Ins::Sign,
            4 => Ins::SignHash,
            0xfe => Ins::GetVersionStr,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use arrayvec::ArrayVec;
use nanos_sdk::io::Reply;

use ledger_parser_combinators::interp_parser::{InterpParser, ParserCommon};
fn run_parser_apdu<P: InterpParser<A, Returning = ArrayVec<u8, 128>>, A>(
    states: &mut ParsersState,
    get_state: fn(&mut ParsersState) -> &mut <P as ParserCommon<A>>::State,
    parser: &P,
    comm: &mut io::Comm,
) -> Result<(), Reply> {
    let cursor = comm.get_data()?;

    loop {
        trace!("Parsing APDU input: {:?}\n", cursor);
        let mut parse_destination = None;
        let parse_rv = <P as InterpParser<A>>::parse(parser, get_state(states), cursor, &mut parse_destination);
        trace!("Parser result: {:?}\n", parse_rv);
        match parse_rv {
            // Explicit rejection; reset the parser. Possibly send error message to host?
            Err((Some(OOB::Reject), _)) => {
                reset_parsers_state(states);
                break Err(io::StatusWords::Unknown.into());
            }
            // Deliberately no catch-all on the Err((Some case; we'll get error messages if we
            // add to OOB's out-of-band actions and forget to implement them.
            //
            // Finished the chunk with no further actions pending, but not done.
            Err((None, [])) => { trace!("Parser needs more; continuing"); break Ok(()) }
            // Didn't consume the whole chunk; reset and error message.
            Err((None, _)) => {
                reset_parsers_state(states);
                break Err(io::StatusWords::Unknown.into());
            }
            // Consumed the whole chunk and parser finished; send response.
            Ok([]) => {
                trace!("Parser finished, resetting state\n");
                match parse_destination.as_ref() {
                    Some(rv) => comm.append(&rv[..]),
                    None => break Err(io::StatusWords::Unknown.into()),
                }
                // Parse finished; reset.
                reset_parsers_state(states);
                break Ok(());
            }
            // Parse ended before the chunk did; reset.
            Ok(_) => {
                reset_parsers_state(states);
                break Err(io::StatusWords::Unknown.into());
            }
        }
    }
}

#[inline(never)]
fn handle_apdu(comm: &mut io::Comm, ins: Ins, parser: &mut ParsersState) -> Result<(), Reply> {
    info!("entering handle_apdu with command {:?}", ins);
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetVersion => {
            comm.append(&[env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(), env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(), env!("CARGO_PKG_VERSION_PATCH").parse().unwrap()]);
            comm.append(b"Kadena");
        }
        Ins::GetPubkey => {
            run_parser_apdu::<_, Bip32Key>(parser, get_get_address_state, &GET_ADDRESS_IMPL, comm)?
        }
        Ins::Sign => {
            run_parser_apdu::<_, SignParameters>(parser, get_sign_state, &SIGN_IMPL, comm)?
        }
        Ins::SignHash => {
            if get_current_settings() != 1 {
                return Err(io::SyscallError::NotSupported.into());
            } else {
                run_parser_apdu::<_, SignHashParameters>(parser, get_sign_hash_state, &SIGN_HASH_IMPL, comm)?
            }
        }
        Ins::GetVersionStr => {
            comm.append(concat!("Kadena ", env!("CARGO_PKG_VERSION")).as_ref());
        }
        Ins::Exit => nanos_sdk::exit_app(0),
    }
    Ok(())
}


pub struct Menu {
    screens_len: usize,
    state: usize,
}

impl Menu {
    pub fn new(init_screens: &[& str]) -> Menu {
        Menu {
            screens_len: init_screens.len(),
            state: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = 0;
    }

    #[inline(never)]
    pub fn show(&mut self, screens: &[& str]) {
        self.screens_len = screens.len();
        self.state = core::cmp::min(self.state, (self.screens_len)-1);
        SingleMessage::new(screens[self.state]).show();
    }

    #[inline(never)]
    pub fn update(&mut self, btn: ButtonEvent) -> Option<usize> {
        match btn {
            ButtonEvent::LeftButtonRelease => self.state = if self.state > 0 { self.state - 1 } else {0},
            ButtonEvent::RightButtonRelease => self.state = core::cmp::min(self.state+1, (self.screens_len)-1),
            ButtonEvent::BothButtonsRelease => return Some(self.state),
            _ => (),
        }
        None
    }
}
