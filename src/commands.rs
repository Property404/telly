macro_rules! impl_telnet_command_enum {
    (
        $(
            $(
                #[doc = $doc:expr]
            )*
            $name: ident = $value: expr,
        )*
    ) => {
        #[derive(Copy, Clone, Debug, PartialEq)]
        /// Telnet commands listed in [RFC854](https://www.rfc-editor.org/rfc/rfc854).
        /// These do not include commands the imply negotiations or subnegotiations, like
        /// WILL, DO, SB, etc.
        pub enum TelnetCommand {
            $(
                $(
                    #[doc = $doc]
                )*
                $name,
            )*
            /// Some other Telnet command not listed.
            Other(u8)
        }

        impl From<TelnetCommand> for u8 {
            fn from(command: TelnetCommand) -> u8 {
                match command {
                    $(
                        TelnetCommand::$name => $value,
                    )*
                    TelnetCommand::Other(byte) => byte
                }
            }
        }

        impl From<u8> for TelnetCommand {
            fn from(byte: u8) -> Self {
                match byte {
                    $(
                        $value => TelnetCommand::$name,
                    )*
                    byte => TelnetCommand::Other(byte)
                }
            }
        }
    }
}

impl_telnet_command_enum! {
    /// No operation.
    Nop = 0xf1,
    /// The data stream portion of a Synch. This should always be accompanied by a TCP Urgent notification.
    DataMark = 0xf2,
    /// NVT character BRK.
    Break = 0xf3,
    /// Suspend, interrupt, abort or terminate the process to which the NVT is connected. Also,
    /// part of the out-of-band signal for other protocols which use Telnet
    InterruptProcess = 0xf4,
    /// Allow the current process to (appear to) run to completion, but do not send its output to
    /// the user. Also, send a Synch to the user.
    AbortOutput = 0xf5,
    /// It's me, Margaret. Tell the receive to send back to the NVT some visible (i.e., printable)
    /// evidence that the AYT was received. This function may be invoked by the user when the
    /// system is unexpectedly "silent" for a long time, because of the unanticipated (by the user)
    /// length of a computation, an unusually heavy system load, etc. AYT is the standard
    /// representation for invoking this function.
    AreYouThere = 0xf6,
    /// Inform the recipient that they should delete the last preceding undeleted character or
    /// "print position" from the data stream.
    EraseCharacter = 0xf7,
    /// Inform the recipient that they should delete characters from the data stream back to, but
    /// not including, the last "CR LF" sequence sent over the Telnet connection.
    EraseLine = 0xf8,
    /// The GA signal.
    GoAhead = 0xf9,
}
