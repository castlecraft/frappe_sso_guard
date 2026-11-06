// Copyright (c) 2026, International Committee of the Red Cross and contributors
// For license information, please see license.txt

frappe.ui.form.on("SSO Identity Settings", {
	refresh(frm) {
		// A save refreshes the form without reloading it, and the warning would outlive a schedule taken off.
		frm.set_intro();
		const schedule = frm.doc.reconciliation_frequency;
		if (
			frm.doc.__onload?.scheduler_inactive &&
			frm.doc.enable_reconciliation &&
			schedule &&
			schedule !== "By Hand"
		) {
			frm.set_intro(
				__(
					"Frappe's scheduler is off on this site, so scheduled reconciliation will not run. A System Manager can use Run Reconciliation meanwhile, and whoever runs the server can turn the scheduler on with bench enable-scheduler."
				),
				"red"
			);
		}
		if (frm.doc.enable_reconciliation && !frm.is_dirty()) {
			frm.add_custom_button(__("Run Reconciliation"), () => frm.call("run_reconciliation"));
		}
	},
});
