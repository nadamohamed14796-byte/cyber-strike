-- Preserve the complete captured JavaScript separately from the capped prompt preview.
-- The full body is used only by static source analysis and is never added to the normal request prompt.
ALTER TABLE request ADD COLUMN javascript_source TEXT;
