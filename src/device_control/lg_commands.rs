//! LG webOS TV command library and capability detection. Defines the set of
//! available remote control commands and queries device capabilities.

use super::lg::LgController;
use super::lg_pairing;
use super::types::{CommandInfo, DeviceCapabilities};

/// Return the list of predefined TV commands (navigation, volume, playback, power).
pub(crate) fn get_commands() -> Vec<CommandInfo> {
    vec![
        CommandInfo {
            id: "ssap://com.webos.service.ime/sendEnterKey".into(),
            name: "OK".into(),
            icon: "\u{23fa}\u{fe0f}".into(),
            category: "Navigation".into(),
        },
        CommandInfo {
            id: "ssap://com.webos.service.tv.display/set3DOn".into(),
            name: "3D On".into(),
            icon: "\u{1f453}".into(),
            category: "Display".into(),
        },
        CommandInfo {
            id: "ssap://com.webos.service.tv.display/set3DOff".into(),
            name: "3D Off".into(),
            icon: "\u{1f4fa}".into(),
            category: "Display".into(),
        },
        CommandInfo {
            id: "ssap://audio/volumeUp".into(),
            name: "Volume Up".into(),
            icon: "\u{1f50a}".into(),
            category: "Volume".into(),
        },
        CommandInfo {
            id: "ssap://audio/volumeDown".into(),
            name: "Volume Down".into(),
            icon: "\u{1f509}".into(),
            category: "Volume".into(),
        },
        CommandInfo {
            id: "ssap://audio/setMute".into(),
            name: "Mute".into(),
            icon: "\u{1f507}".into(),
            category: "Volume".into(),
        },
        CommandInfo {
            id: "ssap://tv/channelUp".into(),
            name: "Channel Up".into(),
            icon: "\u{1f4fa}+".into(),
            category: "Channel".into(),
        },
        CommandInfo {
            id: "ssap://tv/channelDown".into(),
            name: "Channel Down".into(),
            icon: "\u{1f4fa}-".into(),
            category: "Channel".into(),
        },
        CommandInfo {
            id: "ssap://media.controls/play".into(),
            name: "Play".into(),
            icon: "\u{25b6}\u{fe0f}".into(),
            category: "Playback".into(),
        },
        CommandInfo {
            id: "ssap://media.controls/pause".into(),
            name: "Pause".into(),
            icon: "\u{23f8}\u{fe0f}".into(),
            category: "Playback".into(),
        },
        CommandInfo {
            id: "ssap://media.controls/stop".into(),
            name: "Stop".into(),
            icon: "\u{23f9}\u{fe0f}".into(),
            category: "Playback".into(),
        },
        CommandInfo {
            id: "ssap://media.controls/rewind".into(),
            name: "Rewind".into(),
            icon: "\u{23ea}".into(),
            category: "Playback".into(),
        },
        CommandInfo {
            id: "ssap://media.controls/fastForward".into(),
            name: "Fast Forward".into(),
            icon: "\u{23e9}".into(),
            category: "Playback".into(),
        },
        CommandInfo {
            id: "ssap://system/turnOff".into(),
            name: "Power Off".into(),
            icon: "\u{23fb}".into(),
            category: "Power".into(),
        },
        CommandInfo {
            id: "ssap://tv/switchInput".into(),
            name: "Switch Input".into(),
            icon: "\u{1f50c}".into(),
            category: "Other".into(),
        },
        CommandInfo {
            id: "ssap://com.webos.service.capture/executeRecordScreen".into(),
            name: "Screen Capture".into(),
            icon: "\u{1f4f7}".into(),
            category: "Other".into(),
        },
    ]
}

/// Return the device capability list for an LG TV.
pub(crate) fn get_capabilities(ip: &str) -> DeviceCapabilities {
    let has_key = lg_pairing::get_client_key(ip).is_some();
    let device_info = if has_key {
        LgController::get_device_info(ip)
    } else {
        None
    };
    let apps = if has_key {
        LgController::get_apps(ip)
    } else {
        Vec::new()
    };
    let commands = get_commands();

    DeviceCapabilities {
        device_type: "lg".to_string(),
        can_control: true,
        commands,
        apps,
        device_info,
        needs_pairing: !has_key,
        is_paired: has_key,
    }
}
