// BIP-39 mnemonic generator with a tiny native (egui) UI.
//
// Pure generator: every mnemonic is a brand-new random wallet derived from the
// operating system CSPRNG. It does no network access and no balance lookups.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod derive;
mod job;

use bip39::Mnemonic;
use eframe::egui;

/// Number of mnemonic lines shown in the text box before truncating the
/// on-screen preview (the full set is still kept for Copy / Save).
const MAX_PREVIEW_LINES: usize = 1000;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 640.0])
            .with_min_inner_size([440.0, 380.0]),
        ..Default::default()
    };
    eframe::run_native(
        "BIP-39 Mnemonic Generator",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}

struct App {
    count: u32,
    words: usize,
    derive: bool,
    save_path: String,
    /// Full generated text — used by Copy all / Save to file.
    output: String,
    /// Possibly-truncated copy used only for on-screen display.
    preview: String,
    status: String,
    /// In-flight background generation job, if any.
    job: Option<job::RunningJob>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            count: 10,
            words: 12,
            derive: false,
            save_path: "mnemonics.txt".to_owned(),
            output: String::new(),
            preview: String::new(),
            status: "Ready.".to_owned(),
            job: None,
        }
    }
}

/// Entropy length in bytes for a given BIP-39 word count.
/// 12→16, 15→20, 18→24, 21→28, 24→32 bytes.
fn entropy_len(words: usize) -> usize {
    (words / 3) * 4
}

/// Generate one random English BIP-39 mnemonic with the given word count.
pub(crate) fn generate_one(words: usize) -> Result<String, String> {
    let mut entropy = vec![0u8; entropy_len(words)];
    getrandom::fill(&mut entropy).map_err(|e| e.to_string())?;
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())?;
    Ok(mnemonic.to_string())
}

impl App {
    /// Kick off generation on background threads. Returns immediately.
    fn start_job(&mut self) {
        if self.job.is_some() {
            return;
        }
        let count = self.count.max(1) as usize;
        self.status = format!("Generating {count}…");
        self.job = Some(job::start(count, self.words, self.derive));
    }

    /// Store a finished result: keep the full text, build a bounded preview.
    fn apply_output(&mut self, full: String) {
        let line_count = full.lines().count();
        self.preview = if line_count > MAX_PREVIEW_LINES {
            let head: Vec<&str> = full.lines().take(MAX_PREVIEW_LINES).collect();
            format!(
                "{}\n… {} more lines — use \"Save to file\" to get them all.",
                head.join("\n"),
                line_count - MAX_PREVIEW_LINES
            )
        } else {
            full.clone()
        };
        self.output = full;
    }

    /// Poll the background job; apply its result once it finishes.
    fn poll_job(&mut self) {
        let finished = self.job.as_ref().and_then(|j| j.try_take());
        if let Some(result) = finished {
            self.apply_output(result.text);
            self.status = if result.cancelled {
                format!("Cancelled — kept {} mnemonic(s).", result.produced)
            } else {
                format!(
                    "Generated {} × {}-word mnemonic(s).",
                    result.produced, self.words
                )
            };
            self.job = None;
        }
    }

    fn save(&mut self) {
        if self.output.is_empty() {
            self.status = "Nothing to save — generate first.".to_owned();
            return;
        }
        if self.save_path.trim().is_empty() {
            self.status = "Please enter a file name.".to_owned();
            return;
        }
        match std::fs::write(&self.save_path, &self.output) {
            Ok(()) => {
                let shown = std::fs::canonicalize(&self.save_path)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| self.save_path.clone());
                self.status = format!("Saved to {shown}");
            }
            Err(e) => self.status = format!("Save failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_lengths_match_bip39() {
        assert_eq!(entropy_len(12), 16);
        assert_eq!(entropy_len(15), 20);
        assert_eq!(entropy_len(18), 24);
        assert_eq!(entropy_len(21), 28);
        assert_eq!(entropy_len(24), 32);
    }

    #[test]
    fn generates_valid_mnemonics() {
        for &w in &[12usize, 15, 18, 21, 24] {
            let phrase = generate_one(w).expect("generation should succeed");
            assert_eq!(
                phrase.split_whitespace().count(),
                w,
                "expected {w} words"
            );
            // Re-parse to confirm the BIP-39 checksum is valid.
            let parsed = Mnemonic::parse(&phrase).expect("checksum must validate");
            assert_eq!(parsed.to_string(), phrase);
        }
    }

    #[test]
    fn consecutive_mnemonics_differ() {
        let a = generate_one(12).unwrap();
        let b = generate_one(12).unwrap();
        assert_ne!(a, b);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_job();
        let job_state = self.job.as_ref().map(|j| (j.done(), j.total));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("BIP-39 Mnemonic Generator");
            ui.label("Fresh random English BIP-39 mnemonics — offline, OS CSPRNG.");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Count:");
                ui.add(
                    egui::DragValue::new(&mut self.count)
                        .range(1..=1_000_000)
                        .speed(1.0),
                )
                .on_hover_text(
                    "Runs in the background across all CPU cores.\n\
                     For very large batches, use \"Save to file\".",
                );
                ui.add_space(16.0);
                ui.label("Words:");
                egui::ComboBox::from_id_salt("words")
                    .selected_text(self.words.to_string())
                    .show_ui(ui, |ui| {
                        for w in [12usize, 15, 18, 21, 24] {
                            ui.selectable_value(&mut self.words, w, w.to_string());
                        }
                    });
                ui.add_space(16.0);
                ui.checkbox(&mut self.derive, "Derive addresses").on_hover_text(
                    "BTC  m/84'/0'/0'/0/0  (native segwit, bc1)\n\
                     ETH  m/44'/60'/0'/0/0  (EIP-55; also EVM chains)\n\
                     TRX  m/44'/195'/0'/0/0\n\
                     SOL  m/44'/501'/0'/0'  (Phantom)\n\
                     SUI  m/44'/784'/0'/0'/0'",
                );
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let running = job_state.is_some();
                if ui
                    .add_enabled(!running, egui::Button::new("Generate"))
                    .clicked()
                {
                    self.start_job();
                }
                if ui.button("Copy all").clicked() {
                    if self.output.is_empty() {
                        self.status = "Nothing to copy — generate first.".to_owned();
                    } else {
                        ui.ctx().copy_text(self.output.clone());
                        self.status = "Copied all to clipboard.".to_owned();
                    }
                }
                if ui.button("Save to file").clicked() {
                    self.save();
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.save_path)
                        .desired_width(170.0)
                        .hint_text("file name"),
                );
            });

            if let Some((done, total)) = job_state {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        if let Some(j) = self.job.as_ref() {
                            j.request_cancel();
                        }
                    }
                    let frac = if total > 0 {
                        (done as f32 / total as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .text(format!("{done} / {total}"))
                            .desired_width(280.0),
                    );
                });
                // Keep repainting so progress animates and completion is noticed.
                ui.ctx().request_repaint();
            }

            ui.add_space(4.0);
            ui.label(&self.status);
            ui.separator();

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.preview)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(22),
                    );
                });
        });
    }
}
