use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use mailbot::email::LeiEmail;

fn create_test_email() -> LeiEmail {
    LeiEmail {
        subject: "[PATCH v2 5/10] mm: Fix memory allocation in complex subsystem".to_string(),
        from: "Developer Name <developer@example.com>".to_string(),
        message_id: "<20240101120000.123456-5-developer@example.com>".to_string(),
        in_reply_to: Some("<20240101120000.123456-1-developer@example.com>".to_string()),
        date: "2024-01-01T12:00:00Z".to_string(),
        body: r#"From: Developer Name <developer@example.com>
Subject: [PATCH v2 5/10] mm: Fix memory allocation in complex subsystem
Date: Mon, 1 Jan 2024 12:00:00 +0000

This patch fixes a critical memory allocation issue that occurs when
the system is under heavy load and multiple processes are competing
for resources.

commit abcdef1234567890abcdef1234567890abcdef12 upstream.

The problem was first observed in production systems running kernel
5.10.x where applications would occasionally fail with ENOMEM even
though plenty of memory was available.

Signed-off-by: Developer Name <developer@example.com>
Reviewed-by: Reviewer One <reviewer1@example.com>
Tested-by: Tester Two <tester2@example.com>
---
 mm/page_alloc.c | 15 +++++++++------
 mm/vmscan.c     |  8 ++++++--
 2 files changed, 15 insertions(+), 8 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 1234567..abcdefg 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1000,10 +1000,15 @@ static struct page *get_page_from_freelist(gfp_t gfp_mask, unsigned int order,
             continue;
 
         mark = zone->watermark[alloc_flags & ALLOC_WMARK_MASK];
-        if (!zone_watermark_ok(zone, order, mark,
-                       ac->highest_zoneidx, alloc_flags))
-            continue;
-
+        if (!zone_watermark_ok(zone, order, mark,
+                       ac->highest_zoneidx, alloc_flags)) {
+            /* Try harder if this is a critical allocation */
+            if (gfp_mask & __GFP_HIGH) {
+                mark = min_wmark_pages(zone);
+                if (!zone_watermark_ok(zone, order, mark,
+                               ac->highest_zoneidx, alloc_flags))
+                    continue;
+            }
+        }
         /*
          * Try to allocate from CMA area
          */
-- 
2.34.1
"#.to_string(),
        headers: None,
        references: None,
        cc: Some(vec!["stable@vger.kernel.org".to_string()]),
        to: Some(vec!["linux-mm@kvack.org".to_string()]),
    }
}

fn bench_is_git_patch(c: &mut Criterion) {
    let email = create_test_email();
    
    c.bench_function("is_git_patch", |b| {
        b.iter(|| {
            black_box(email.is_git_patch())
        })
    });
}

fn bench_extract_series_info(c: &mut Criterion) {
    let email = create_test_email();
    
    c.bench_function("extract_series_info", |b| {
        b.iter(|| {
            black_box(email.extract_series_info())
        })
    });
}

fn bench_clean_subject(c: &mut Criterion) {
    let email = create_test_email();
    
    c.bench_function("clean_subject", |b| {
        b.iter(|| {
            black_box(email.clean_subject())
        })
    });
}

fn bench_decode_mime_header(c: &mut Criterion) {
    let encoded = "=?UTF-8?B?W1BBVENIIHYyIDUvMTBdIG1tOiBGaXggbWVtb3J5IGFsbG9jYXRpb24gaW4gY29tcGxleCBzdWJzeXN0ZW0=?=";
    
    c.bench_function("decode_mime_header", |b| {
        b.iter(|| {
            black_box(LeiEmail::decode_mime_header(encoded))
        })
    });
}

fn bench_normalized_from(c: &mut Criterion) {
    let email = create_test_email();
    
    c.bench_function("normalized_from", |b| {
        b.iter(|| {
            black_box(email.normalized_from())
        })
    });
}

criterion_group!(
    benches,
    bench_is_git_patch,
    bench_extract_series_info,
    bench_clean_subject,
    bench_decode_mime_header,
    bench_normalized_from
);
criterion_main!(benches);