use kadena::implementation::*;
use kadena::interface::*;
use ledger_parser_combinators::interp_parser::set_from_thunk;

use nanos_sdk::io;
use nanos_sdk::buttons::{ButtonEvent};
use nanos_ui::ui::{SingleMessage};

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

use ledger_parser_combinators::interp_parser::OOB;
use kadena::*;

#[cfg(not(test))]
#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    let mut states = ParsersState::NoState;
    let idle_menu: [&str; 3] = [ concat!("Kadena ", env!("CARGO_PKG_VERSION")), "Exit", "Settings" ];
    let busy_menu: [&str; 2] = [ "Working...", "Cancel" ];
    let settings_menu_1: [&str; 2] = [ "Enable Hash Signing", "Back" ];
    let settings_menu_2: [&str; 2] = [ "Disable Hash Signing", "Back" ];
    let mut menu = Menu::new(&idle_menu);

    info!("Kadena app {}", env!("CARGO_PKG_VERSION"));

    loop {
        // Draw some 'welcome' screen
        match states {
            ParsersState::NoState => menu.show(&idle_menu),
            ParsersState::SettingsState(0) => menu.show(&settings_menu_1),
            ParsersState::SettingsState(1) => menu.show(&settings_menu_2),
            _ => menu.show(&busy_menu),
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
            io::Event::Button(btn) => match states {
                ParsersState::NoState => {match menu.update(btn) {
                    Some(1) => { info!("Exiting app at user direction via root menu"); nanos_sdk::exit_app(0) },
                    Some(2) => { menu.reset(); states = ParsersState::SettingsState(0); },
                    _ => (),
                } }
                ParsersState::SettingsState(0) => {match menu.update(btn) {
                    Some(0) => { states = ParsersState::SettingsState(1); },
                    Some(1) => { menu.reset(); states = ParsersState::NoState; },
                    _ => (),
                } }
                ParsersState::SettingsState(1) => {match menu.update(btn) {
                    Some(0) => { states = ParsersState::SettingsState(0); },
                    Some(1) => { menu.reset(); states = ParsersState::NoState; },
                    _ => (),
                } }
                _ => { match menu.update(btn) {
                    Some(1) => { info!("Resetting at user direction via busy menu"); menu.reset(); set_from_thunk(&mut states, || ParsersState::NoState); }
                    _ => (),
                } }
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
    GetVersionStr,
    Exit
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            0 => Ins::GetVersion,
            2 => Ins::GetPubkey,
            3 => Ins::Sign,
            0xfe => Ins::GetVersionStr,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use arrayvec::ArrayVec;
use nanos_sdk::io::Reply;

use ledger_parser_combinators::interp_parser::InterpParser;
fn run_parser_apdu<P: InterpParser<A, Returning = ArrayVec<u8, 128>>, A>(
    states: &mut ParsersState,
    get_state: fn(&mut ParsersState) -> &mut <P as InterpParser<A>>::State,
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

// fn handle_apdu<P: for<'a> FnMut(ParserTag, &'a [u8]) -> RX<'a, ArrayVec<u8, 260> > >(comm: &mut io::Comm, ins: Ins, parser: &mut P) -> Result<(), Reply> {
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
        Ins::GetVersionStr => {
            comm.append(concat!("Kadena ", env!("CARGO_PKG_VERSION")).as_ref());
        }
        Ins::Exit => nanos_sdk::exit_app(0),
    }
    Ok(())
}


pub struct Menu<'a> {
    screens: &'a[&'a str],
    state: usize,
}

impl<'a> Menu<'a> {
    pub fn new(init_screens: &'a[&'a str]) -> Menu<'a> {
        Menu {
            screens: init_screens,
            state: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = 0;
    }

    #[inline(never)]
    pub fn show(&mut self, screens: &'a[&'a str]) {
        self.screens = screens;
        self.state = core::cmp::min(self.state, (self.screens.len())-1);
        SingleMessage::new(self.screens[self.state]).show();
    }

    #[inline(never)]
    pub fn update(&mut self, btn: ButtonEvent) -> Option<usize> {
        match btn {
            ButtonEvent::LeftButtonRelease => self.state = if self.state > 0 { self.state - 1 } else {0},
            ButtonEvent::RightButtonRelease => self.state = core::cmp::min(self.state+1, (self.screens.len())-1),
            ButtonEvent::BothButtonsRelease => return Some(self.state),
            _ => (),
        }
        None
    }
}
