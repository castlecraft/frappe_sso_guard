// Copyright (c) 2026, International Committee of the Red Cross and contributors
// For license information, please see license.txt

frappe.ui.form.on("SSO Identity Settings", {
	refresh(frm) {
		if (frm.doc.enable_reconciliation && !frm.is_dirty()) {
			frm.add_custom_button(__("Run Reconciliation"), () => frm.call("run_reconciliation"));
		}
	},
});
