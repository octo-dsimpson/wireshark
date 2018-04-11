/* packet_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_dialog.h"
#include <ui_packet_dialog.h>

#include "file.h"

#include "epan/column.h"
#include "epan/ftypes/ftypes.h"

#include "frame_tvbuff.h"

#include <wsutil/utf8_entities.h>

#include "byte_view_tab.h"
#include "proto_tree.h"
#include "wireshark_application.h"

#include <ui/qt/utils/field_information.h>
#include <QTreeWidgetItemIterator>
#include<Windows.h>

// To do:
// - Copy over experimental packet editing code.
// - Fix ElidedText width.

PacketDialog::PacketDialog(QWidget &parent, CaptureFile &cf, frame_data *fdata) :
    WiresharkDialog(parent, cf),
    ui(new Ui::PacketDialog),
    proto_tree_(NULL),
    byte_view_tab_(NULL),
    rec_(wtap_rec()),
    packet_data_(NULL)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    ui->hintLabel->setSmallText();
    edt_.session = NULL;
    edt_.tvb = NULL;
    edt_.tree = NULL;

    memset(&edt_.pi, 0x0, sizeof(edt_.pi));

    setWindowSubtitle(tr("Packet %1").arg(fdata->num));

    if (!cf_read_record(cap_file_.capFile(), fdata)) {
        reject();
        return;
    }

    rec_ = cap_file_.capFile()->rec;

#ifndef __clang_analyzer__
    packet_data_ = (guint8 *) g_memdup(ws_buffer_start_ptr(&(cap_file_.capFile()->buf)), fdata->cap_len);
#endif

    /* proto tree, visible. We need a proto tree if there's custom columns */
    epan_dissect_init(&edt_, cap_file_.capFile()->epan, TRUE, TRUE);
    col_custom_prime_edt(&edt_, &(cap_file_.capFile()->cinfo));

    epan_dissect_run(&edt_, cap_file_.capFile()->cd_t, &rec_,
                     frame_tvbuff_new(&cap_file_.capFile()->provider, fdata, packet_data_),
                     fdata, &(cap_file_.capFile()->cinfo));
    epan_dissect_fill_in_columns(&edt_, TRUE, TRUE);

    proto_tree_ = new ProtoTree(ui->packetSplitter);
    proto_tree_->setRootNode(edt_.tree);

    byte_view_tab_ = new ByteViewTab(ui->packetSplitter, &edt_);
    byte_view_tab_->setCaptureFile(cap_file_.capFile());
    byte_view_tab_->selectedFrameChanged(0);

    ui->packetSplitter->setStretchFactor(1, 0);

    QStringList col_parts;
    for (int i = 0; i < cap_file_.capFile()->cinfo.num_cols; ++i) {
        // ElidedLabel doesn't support rich text / HTML
        col_parts << QString("%1: %2")
                     .arg(get_column_title(i))
                     .arg(cap_file_.capFile()->cinfo.columns[i].col_data);
    }
    col_info_ = col_parts.join(" " UTF8_MIDDLE_DOT " ");

    ui->hintLabel->setText(col_info_);

    connect(wsApp, SIGNAL(zoomMonospaceFont(QFont)),
            proto_tree_, SLOT(setMonospaceFont(QFont)));

    connect(byte_view_tab_, SIGNAL(fieldSelected(FieldInformation *)),
            proto_tree_, SLOT(selectedFieldChanged(FieldInformation *)));
    connect(proto_tree_, SIGNAL(fieldSelected(FieldInformation *)),
            byte_view_tab_, SLOT(selectedFieldChanged(FieldInformation *)));

    connect(byte_view_tab_, SIGNAL(fieldHighlight(FieldInformation *)),
            this, SLOT(setHintText(FieldInformation *)));

    STARTUPINFOA startup_info={sizeof(startup_info)};
    PROCESS_INFORMATION process_information;
    int base_frame_num;
    if(this->rec_.opt_comment != NULL){
        base_frame_num = atoi(this->rec_.opt_comment);
    }else{
        base_frame_num = 0;
    }
    QString process = QString("C:\\Python27\\python.exe C:\\octoScope\\oct.py %1 %2").arg(fdata->num).arg(base_frame_num);
    //LPSTR s = (LPSTR)process.toLocal8Bit().constData();
    //QString params = QString("C:\\Development\\octoScopeNI.py 3");
    //QString params = QString("C:\\o.py 3");
    //const char *s = ()params.utf8();
    /*std::wstring params = L"C:\\Development\\octoScopeNI.py " + fdata->num;
    LPWSTR s = const_cast<wchar_t *>(params.c_str());*/
    //char *z = "C:\\Python27\\python.exe";
    //LPSTR s = (LPSTR)params.toLocal8Bit().constData();
    CreateProcessA(NULL, (LPSTR)process.toLocal8Bit().constData(), NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_information);
}

PacketDialog::~PacketDialog()
{
    delete ui;
    epan_dissect_cleanup(&edt_);
    g_free(packet_data_);
}

void PacketDialog::captureFileClosing()
{
    QString closed_title = tr("[%1 closed] " UTF8_MIDDLE_DOT " %2")
            .arg(cap_file_.fileName())
            .arg(col_info_);
    ui->hintLabel->setText(closed_title);
    WiresharkDialog::captureFileClosing();
}

void PacketDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_NEW_PACKET_DIALOG);
}

void PacketDialog::setHintText(FieldInformation * finfo)
{
    QString hint;

     if ( finfo )
     {
         FieldInformation::Position pos = finfo->position();
         QString field_str;

         if (pos.length < 2) {
             hint = QString(tr("Byte %1")).arg(pos.start);
         } else {
             hint = QString(tr("Bytes %1-%2")).arg(pos.start).arg(pos.start + pos.length - 1);
         }
         hint += QString(": %1 (%2)")
                 .arg(finfo->headerInfo().name)
                 .arg(finfo->headerInfo().abbreviation);
     }
     ui->hintLabel->setText(hint);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
