use nanos_sdk::buttons::{ButtonsState, ButtonEvent};
use nanos_ui::bagls::*;
use nanos_ui::ui::{get_event, MessageValidator};
use arrayvec::ArrayString;
use core::fmt::Write;
use ledger_log::trace;

pub struct PromptWrite<'a, const N: usize> {
    offset: usize,
    buffer: &'a mut ArrayString<N>,
    total: usize
}

impl<'a, const N: usize> Write for PromptWrite<'a, N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.total += s.len();
        let offset_in_s = core::cmp::min(self.offset, s.len());
        self.offset -= offset_in_s;
        if self.offset > 0 {
            return Ok(());
        }
        self.buffer.try_push_str(
            &s[offset_in_s .. core::cmp::min(s.len(), offset_in_s + self.buffer.remaining_capacity())]
        ).map_err(|_| core::fmt::Error)
    }
}

pub fn final_accept_prompt(prompt: &[&str]) -> Option<()> {
    if !MessageValidator::new(prompt, &[&"Confirm"], &[&"Reject"]).ask() {
        trace!("User rejected at end\n");
        None
    } else {
        trace!("User accepted");
        Some(())
    }
}

pub fn write_scroller< F: for <'b> Fn(&mut PromptWrite<'b, 16>) -> core::fmt::Result > (title: &str, prompt_function: F) -> Option<()> {
    if !WriteScroller::<_, 16>::new(title, prompt_function).ask() {
        trace!("User rejected prompt");
        None
    } else {
        Some(())
    }
}

pub struct WriteScroller<'a, F: for<'b> Fn(&mut PromptWrite<'b, CHAR_N>) -> core::fmt::Result, const CHAR_N: usize> {
    title: &'a str,
    contents: F
}

const RIGHT_CHECK : Icon = Icon::new(Icons::Check).pos(120,12);

impl<'a, F: for<'b> Fn(&mut PromptWrite<'b, CHAR_N>) -> core::fmt::Result, const CHAR_N: usize> WriteScroller<'a, F, CHAR_N> {

    pub fn new(title: &'a str, contents: F) -> Self {
        WriteScroller { title, contents }
    }

    fn get_length(&self) -> Result<usize, core::fmt::Error> {
        let mut buffer = ArrayString::new();
        let mut prompt_write = PromptWrite{ offset: 0, buffer: &mut buffer, total: 0 };
        (self.contents)(&mut prompt_write)?;
        let length = prompt_write.total;
        Ok(length)
    }

    pub fn ask(&self) -> bool {
        self.ask_err().unwrap_or(false)
    }

    pub fn ask_err(&self) -> Result<bool, core::fmt::Error> {
        let mut buttons = ButtonsState::new();
        let page_count = (self.get_length()?-1) / CHAR_N + 1;
        if page_count == 0 {
            return Ok(true);
        }
        let title_label = LabelLine::new().pos(0, 10).text(self.title);
        let label = LabelLine::new().pos(0,25); 
        let mut cur_page = 0;

        // A closure to draw common elements of the screen
        // cur_page passed as parameter to prevent borrowing
        let draw = |page: usize| -> core::fmt::Result {
            let offset = page * CHAR_N;
            let mut buffer = ArrayString::new();
            (self.contents)(&mut PromptWrite{ offset, buffer: &mut buffer, total: 0 })?;
            label.text(buffer.as_str()).display();
            title_label.paint();
            if page > 0 {
                LEFT_ARROW.paint();
            }
            if page + 2 < page_count {
                RIGHT_ARROW.paint();
            } else {
                RIGHT_CHECK.paint();
            }
            Ok(())
        };

        draw(cur_page);

        loop {
            match get_event(&mut buttons) {
                Some(ButtonEvent::LeftButtonPress) => {
                    LEFT_S_ARROW.paint();
                }
                Some(ButtonEvent::RightButtonPress) => {
                    RIGHT_S_ARROW.paint();
                }
                Some(ButtonEvent::LeftButtonRelease) => {
                    if cur_page > 0 {
                        cur_page -= 1;
                    }
                    // We need to draw anyway to clear button press arrow
                    draw(cur_page);
                }    
                Some(ButtonEvent::RightButtonRelease) => {
                    if cur_page + 1 < page_count {
                        cur_page += 1;
                    }
                    if cur_page + 1 == page_count {
                        break Ok(true);
                    }
                    // We need to draw anyway to clear button press arrow
                    draw(cur_page);
                }
                Some(ButtonEvent::BothButtonsRelease) => break Ok(false),
                Some(_) | None => ()
            }
        }
    }
}
