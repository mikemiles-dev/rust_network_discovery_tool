//! Excel export and file upload/import API endpoints.

use actix_multipart::Multipart;
use actix_web::{HttpResponse, Responder, get, post};
use futures_util::StreamExt;
use rust_xlsxwriter::{Format, Workbook};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;

use crate::db::{SQLWriter, get_setting_i64};
use crate::network::endpoint::{
    characterize_model, characterize_vendor, get_mac_vendor,
};

use crate::web::{
    COMPONENT_VENDORS, DEFAULT_ACTIVE_THRESHOLD_SECONDS, DEFAULT_SCAN_INTERVAL_MINUTES,
    dropdown_endpoints, get_all_endpoint_types, get_all_endpoints_last_seen,
    get_all_endpoints_online_status, get_endpoint_ips_and_macs, get_endpoint_ssdp_models,
};

// ============================================================================
// Export Endpoints
// ============================================================================

#[get("/api/export/endpoints.xlsx")]
pub async fn export_endpoints_xlsx() -> impl Responder {
    let scan_interval: u64 = DEFAULT_SCAN_INTERVAL_MINUTES;

    // Get endpoint list
    let dropdown_future = tokio::task::spawn_blocking(move || dropdown_endpoints(scan_interval));
    let dropdown_endpoints_list = dropdown_future.await.unwrap_or_default();

    if dropdown_endpoints_list.is_empty() {
        return HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header((
                "Content-Disposition",
                "attachment; filename=\"endpoints.xlsx\"",
            ))
            .body(Vec::new());
    }

    // Run queries in parallel (same as get_endpoints_table)
    let dropdown_for_ips = dropdown_endpoints_list.clone();
    let dropdown_for_seen = dropdown_endpoints_list.clone();
    let dropdown_for_online = dropdown_endpoints_list.clone();
    let dropdown_for_types = dropdown_endpoints_list.clone();
    let dropdown_for_ssdp = dropdown_endpoints_list.clone();

    let ips_macs_future =
        tokio::task::spawn_blocking(move || get_endpoint_ips_and_macs(&dropdown_for_ips));
    let last_seen_future = tokio::task::spawn_blocking(move || {
        get_all_endpoints_last_seen(&dropdown_for_seen, scan_interval)
    });
    let online_status_future = tokio::task::spawn_blocking(move || {
        let active_threshold = get_setting_i64("active_threshold_seconds", DEFAULT_ACTIVE_THRESHOLD_SECONDS) as u64;
        get_all_endpoints_online_status(&dropdown_for_online, active_threshold)
    });
    let all_types_future =
        tokio::task::spawn_blocking(move || get_all_endpoint_types(&dropdown_for_types));
    let ssdp_models_future =
        tokio::task::spawn_blocking(move || get_endpoint_ssdp_models(&dropdown_for_ssdp));

    let (
        ips_macs_result,
        last_seen_result,
        online_status_result,
        all_types_result,
        ssdp_models_result,
    ) = tokio::join!(
        ips_macs_future,
        last_seen_future,
        online_status_future,
        all_types_future,
        ssdp_models_future
    );

    let endpoint_ips_macs = ips_macs_result.unwrap_or_default();
    let endpoint_last_seen = last_seen_result.unwrap_or_default();
    let endpoint_online_status = online_status_result.unwrap_or_default();
    let (dropdown_types, _manual_overrides) = all_types_result.unwrap_or_default();
    let endpoint_ssdp_models = ssdp_models_result.unwrap_or_default();

    // Build vendor lookup
    let endpoint_vendors: HashMap<String, String> =
        dropdown_endpoints_list
            .iter()
            .filter_map(|endpoint| {
                let endpoint_lower = endpoint.to_lowercase();
                let (
                    _custom_model,
                    ssdp_model,
                    ssdp_friendly,
                    custom_vendor,
                    snmp_vendor,
                    _snmp_model,
                ) = endpoint_ssdp_models
                    .get(&endpoint_lower)
                    .map(|m| {
                        (
                            m.custom_model.as_deref(),
                            m.ssdp_model.as_deref(),
                            m.ssdp_friendly_name.as_deref(),
                            m.custom_vendor.as_deref(),
                            m.snmp_vendor.as_deref(),
                            m.snmp_model.as_deref(),
                        )
                    })
                    .unwrap_or((None, None, None, None, None, None));

                let macs: Vec<String> = endpoint_ips_macs
                    .get(&endpoint_lower)
                    .map(|(_, m)| m.clone())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|mac| {
                        get_mac_vendor(mac)
                            .map(|v| !COMPONENT_VENDORS.contains(&v))
                            .unwrap_or(true)
                    })
                    .collect();

                characterize_vendor(
                    custom_vendor,
                    ssdp_friendly,
                    snmp_vendor,
                    Some(endpoint.as_str()),
                    &macs,
                    ssdp_model,
                )
                .map(|c| (endpoint_lower, c.value))
            })
            .collect();

    // Build model lookup
    let endpoint_models: HashMap<String, String> = dropdown_endpoints_list
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            let (custom_model, ssdp_model, _, _, _, snmp_model) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|m| {
                    (
                        m.custom_model.as_deref(),
                        m.ssdp_model.as_deref(),
                        m.ssdp_friendly_name.as_deref(),
                        m.custom_vendor.as_deref(),
                        m.snmp_vendor.as_deref(),
                        m.snmp_model.as_deref(),
                    )
                })
                .unwrap_or((None, None, None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default();

            let vendor = endpoint_vendors.get(&endpoint_lower).map(|v| v.as_str());

            characterize_model(
                custom_model,
                ssdp_model,
                snmp_model,
                Some(endpoint.as_str()),
                &macs,
                vendor,
                None,
            )
            .map(|c| (endpoint_lower, c.value))
        })
        .collect();

    // Create Excel workbook
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet.set_name("Endpoints").ok();

    // Header format
    let header_format = Format::new().set_bold();

    // Write headers
    let headers = [
        "Name",
        "IP",
        "MAC",
        "Vendor",
        "Model",
        "Device Type",
        "Last Seen",
        "Online",
    ];
    for (col, header) in headers.iter().enumerate() {
        worksheet
            .write_string_with_format(0, col as u16, *header, &header_format)
            .ok();
    }

    // Write data rows
    for (row_idx, endpoint) in dropdown_endpoints_list.iter().enumerate() {
        let row = (row_idx + 1) as u32;
        let endpoint_lower = endpoint.to_lowercase();

        let (ips, macs) = endpoint_ips_macs
            .get(&endpoint_lower)
            .cloned()
            .unwrap_or_default();

        worksheet.write_string(row, 0, endpoint).ok();
        worksheet.write_string(row, 1, ips.join(", ")).ok();
        worksheet.write_string(row, 2, macs.join(", ")).ok();
        worksheet
            .write_string(
                row,
                3,
                endpoint_vendors
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or(""),
            )
            .ok();
        worksheet
            .write_string(
                row,
                4,
                endpoint_models
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or(""),
            )
            .ok();
        worksheet
            .write_string(
                row,
                5,
                dropdown_types
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or(""),
            )
            .ok();
        worksheet
            .write_string(
                row,
                6,
                endpoint_last_seen
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or("-"),
            )
            .ok();
        worksheet
            .write_string(
                row,
                7,
                if *endpoint_online_status
                    .get(&endpoint_lower)
                    .unwrap_or(&false)
                {
                    "Yes"
                } else {
                    "No"
                },
            )
            .ok();
    }

    // Set column widths for readability
    worksheet.set_column_width(0, 30).ok(); // Name
    worksheet.set_column_width(1, 15).ok(); // IP
    worksheet.set_column_width(2, 20).ok(); // MAC
    worksheet.set_column_width(3, 15).ok(); // Vendor
    worksheet.set_column_width(4, 20).ok(); // Model
    worksheet.set_column_width(5, 15).ok(); // Device Type
    worksheet.set_column_width(6, 20).ok(); // Last Seen
    worksheet.set_column_width(7, 8).ok(); // Online

    // Save to buffer
    let buffer = match workbook.save_to_buffer() {
        Ok(buf) => buf,
        Err(e) => {
            eprintln!("Failed to create Excel file: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create Excel file");
        }
    };

    HttpResponse::Ok()
        .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        .insert_header((
            "Content-Disposition",
            "attachment; filename=\"endpoints.xlsx\"",
        ))
        .body(buffer)
}

// ============================================================================
// PCAP Upload Endpoint
// ============================================================================

#[derive(Serialize)]
pub struct PcapUploadResponse {
    success: bool,
    message: String,
    packet_count: Option<usize>,
    filename: Option<String>,
}

#[post("/api/pcap/upload")]
pub async fn upload_pcap(mut payload: Multipart) -> impl Responder {
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut label: Option<String> = None;

    // Extract file and label from multipart form
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                return HttpResponse::BadRequest().json(PcapUploadResponse {
                    success: false,
                    message: format!("Error reading multipart field: {}", e),
                    packet_count: None,
                    filename: None,
                });
            }
        };

        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "file" {
            // Get filename from content disposition
            if let Some(cd) = field.content_disposition() {
                filename = cd.get_filename().map(|s| s.to_string());
            }

            // Read file data
            let mut data = Vec::new();
            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(bytes) => data.extend_from_slice(&bytes),
                    Err(e) => {
                        return HttpResponse::BadRequest().json(PcapUploadResponse {
                            success: false,
                            message: format!("Error reading file data: {}", e),
                            packet_count: None,
                            filename: None,
                        });
                    }
                }
            }
            file_data = Some(data);
        } else if field_name == "label" {
            // Read label field
            let mut label_data = Vec::new();
            while let Some(chunk) = field.next().await {
                if let Ok(bytes) = chunk {
                    label_data.extend_from_slice(&bytes);
                }
            }
            if let Ok(label_str) = String::from_utf8(label_data) {
                let trimmed = label_str.trim();
                if !trimmed.is_empty() {
                    label = Some(trimmed.to_string());
                }
            }
        }
    }

    // Validate we got a file
    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => {
            return HttpResponse::BadRequest().json(PcapUploadResponse {
                success: false,
                message: "No file uploaded or file is empty".to_string(),
                packet_count: None,
                filename: None,
            });
        }
    };

    let original_filename = filename
        .clone()
        .unwrap_or_else(|| "upload.pcap".to_string());

    // If no label provided, use the filename
    let source_label = label.unwrap_or_else(|| original_filename.clone());

    // Write to temporary file
    let temp_path = format!("/tmp/pcap_upload_{}.pcap", uuid::Uuid::new_v4());
    match std::fs::File::create(&temp_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&data) {
                return HttpResponse::InternalServerError().json(PcapUploadResponse {
                    success: false,
                    message: format!("Failed to write temp file: {}", e),
                    packet_count: None,
                    filename: Some(original_filename),
                });
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(PcapUploadResponse {
                success: false,
                message: format!("Failed to create temp file: {}", e),
                packet_count: None,
                filename: Some(original_filename),
            });
        }
    }

    // Create a SQL writer for processing
    let sql_writer = SQLWriter::new().await;
    let sender = sql_writer.sender.clone();

    // Process the pcap file in a blocking task
    let temp_path_clone = temp_path.clone();
    let label_clone = source_label.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::pcap::process_pcap_file(&temp_path_clone, Some(label_clone), &sender)
    })
    .await;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    // Give the SQL writer time to flush remaining packets
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    match result {
        Ok(Ok(packet_count)) => HttpResponse::Ok().json(PcapUploadResponse {
            success: true,
            message: format!(
                "Successfully processed {} packets from '{}'",
                packet_count, original_filename
            ),
            packet_count: Some(packet_count),
            filename: Some(original_filename),
        }),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(PcapUploadResponse {
            success: false,
            message: format!("Failed to process pcap file: {}", e),
            packet_count: None,
            filename: Some(original_filename),
        }),
        Err(e) => HttpResponse::InternalServerError().json(PcapUploadResponse {
            success: false,
            message: format!("Task execution error: {}", e),
            packet_count: None,
            filename: Some(original_filename),
        }),
    }
}
