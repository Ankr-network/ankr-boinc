// This file is part of BOINC.
// http://boinc.berkeley.edu
// Copyright (C) 2008 University of California
//
// BOINC is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// BOINC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with BOINC.  If not, see <http://www.gnu.org/licenses/>.

// Simple validator framework:
// Lets you create a custom validator by supplying three functions.
// See http://boinc.berkeley.edu/trac/wiki/ValidationSimple
//

#include "config.h"
#include <vector>
#include <cstdlib>
#include <string>


#include "boinc_db.h"
#include "error_numbers.h"

#include "sched_config.h"
#include "sched_msgs.h"

#include "validator.h"
#include "validate_util.h"
#include "validate_util2.h"

using std::vector;

// Given a set of results:
// 1) call init_result() for each one;
//    this detects results with bad or missing output files
// 2) if # of good results is >= wu.min_quorum,
//    check for a canonical result,
//    i.e. a set of at least min_quorum/2+1 results for which
//    that are equivalent according to check_pair().
//
// input invariants:
// for each result:
//   result.outcome == SUCCESS
//   result.validate_state == INIT
//
// Outputs:
// canonicalid: the ID of canonical result, if any
// result.outcome, result.validate_state
//    modified; caller must update DB
// retry: set to true if some result had a transient failure
//    (i.e. there was a broken NFS mount).
//    Should call this again after a while.
//
int check_set(
    vector<RESULT>& results, WORKUNIT& wu,
    DB_ID_TYPE& canonicalid, double&, bool& retry
) {
    vector<void*> data;
    vector<bool> had_error;
    int i, j, neq = 0, n, retval;
    int min_valid = wu.min_quorum/2+1;

    retry = false;
    n = results.size();
    data.resize(n);
    had_error.resize(n);

    // Initialize results

    for (i=0; i<n; i++) {
        data[i] = NULL;
        had_error[i] = false;
    }
    int good_results = 0;
    int suspicious_results = 0;
    for (i=0; i<n; i++) {
        retval = init_result(results[i], data[i]);
        if(retval == BOINC_SUCCESS){
            good_results++;
            if(!canonicalid)canonicalid = results[i].id;
            results[i].validate_state = VALIDATE_STATE_VALID;
        } else  {
            results[i].outcome = RESULT_OUTCOME_VALIDATE_ERROR;
            results[i].validate_state = VALIDATE_STATE_INVALID;
        }
    }
    
    if (good_results < wu.min_quorum) goto cleanup;  // never run here


cleanup:

    for (i=0; i<n; i++) {
        cleanup_result(results[i], data[i]);
    }
    return 0;
}

// r1 is the new result; r2 is canonical result
//
void check_pair(RESULT& r1, RESULT& canonical_result, bool& retry) {
    void* data1;
    void* data2;
    int retval;
    bool match;
   // canonical_result may need compare future. but sgx only test once, no compare logic now
   
    retry = false;
    retval = init_result(r1, data1);
    if(retval == BOINC_SUCCESS){
         r1.validate_state = VALIDATE_STATE_VALID;  
    }else{
        r1.validate_state = VALIDATE_STATE_INVALID; 
    }
    
    cleanup_result(r1, data1);
    //cleanup_result(r2, data2);
}
