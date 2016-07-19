#!/usr/bin/perl

#---------------------------------------------------------------------
#----- Copyright(C) 2016 The Trustees of Indiana University
#---------------------------------------------------------------------
#----- This script makes the Makefile for this module.  Run it using
#----- perl Makefile.PL on the command before running make.
#---------------------------------------------------------------------

use strict;
use warnings;

use ExtUtils::MakeMaker;
use FindBin;

sub MY::postamble { <<"END"; }

rpm: dist
    rpmbuild -ta grnoc-tsds-asn-stats-collector-\$(VERSION).tar.gz

END

WriteMakefile(
    NAME                => 'grnoc-MPLS-LSP-usage-collector',
    AUTHOR              => 'GRNOC Software Engineering',
    VERSION_FROM        => 'lib/GRNOC/MPLS/Collector.pm',
    PL_FILES            => {},
    PREREQ_PM     => {},
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'grnoc-MPLS-LSP-usage-collector*.gz' },
    );
