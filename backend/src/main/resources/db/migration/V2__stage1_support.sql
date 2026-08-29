-- V2__stage1_support.sql
-- Supporting indexes/constraints for CSV upload + Stage1 static identification.

-- Needed for ON CONFLICT upsert during CPE Dictionary sync.
ALTER TABLE cpe_dictionary
    ADD CONSTRAINT uq_cpe_dictionary_cpe_string UNIQUE (cpe_string);

CREATE INDEX idx_research_jobs_user_id ON research_jobs (user_id);

CREATE INDEX idx_research_job_items_job_id ON research_job_items (job_id);

CREATE INDEX idx_identified_products_job_item_id ON identified_products (job_item_id);
