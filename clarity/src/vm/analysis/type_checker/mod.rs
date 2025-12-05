// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pub mod contexts;
pub mod v2_05;
pub mod v2_1;

use funai_common::types::FunaiEpochId;

use super::errors::{
    check_argument_count, check_arguments_at_least, check_arguments_at_most, CheckError,
    CheckErrors, CheckResult,
};
pub use super::types::{AnalysisPass, ContractAnalysis};
use super::AnalysisDatabase;
use crate::vm::costs::{analysis_typecheck_cost, CostTracker, LimitedCostTracker};
use crate::vm::types::signatures::{
    CallableSubtype, FunctionArgSignature, FunctionReturnsSignature,
};
use crate::vm::types::{
    FixedFunction, FunctionType, PrincipalData, SequenceSubtype, StringSubtype, TypeSignature,
};
use crate::vm::{ClarityVersion, Value};

impl FunctionType {
    pub fn check_args<T: CostTracker>(
        &self,
        accounting: &mut T,
        args: &[TypeSignature],
        epoch: FunaiEpochId,
        clarity_version: ClarityVersion,
    ) -> CheckResult<TypeSignature> {
        match epoch {
            FunaiEpochId::Epoch20 | FunaiEpochId::Epoch2_05 => {
                self.check_args_2_05(accounting, args)
            }
            FunaiEpochId::Epoch21
            | FunaiEpochId::Epoch22
            | FunaiEpochId::Epoch23
            | FunaiEpochId::Epoch24
            | FunaiEpochId::Epoch25
            | FunaiEpochId::Epoch30 => self.check_args_2_1(accounting, args, clarity_version),
            FunaiEpochId::Epoch10 => {
                return Err(CheckErrors::Expects("Epoch10 is not supported".into()).into())
            }
        }
    }

    pub fn check_args_by_allowing_trait_cast(
        &self,
        db: &mut AnalysisDatabase,
        func_args: &[Value],
        epoch: FunaiEpochId,
        clarity_version: ClarityVersion,
    ) -> CheckResult<TypeSignature> {
        match epoch {
            FunaiEpochId::Epoch20 | FunaiEpochId::Epoch2_05 => {
                self.check_args_by_allowing_trait_cast_2_05(db, func_args)
            }
            FunaiEpochId::Epoch21
            | FunaiEpochId::Epoch22
            | FunaiEpochId::Epoch23
            | FunaiEpochId::Epoch24
            | FunaiEpochId::Epoch25
            | FunaiEpochId::Epoch30 => {
                self.check_args_by_allowing_trait_cast_2_1(db, clarity_version, func_args)
            }
            FunaiEpochId::Epoch10 => {
                return Err(CheckErrors::Expects("Epoch10 is not supported".into()).into())
            }
        }
    }
}
