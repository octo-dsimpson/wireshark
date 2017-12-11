/* packet_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include <QTreeWidgetItemIterator>
#include<Windows.h>

// To do:
// - Copy over experimental packet editing code.
// - Fix ElidedText width.

PacketDialog::PacketDialog(QWidget &parent, CaptureFile &cf, frame_data *fdata) :
    WiresharkDialog(parent, cf),
    ui(new Ui::PacketDialog),
    packet_data_(NULL)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    ui->hintLabel->setSmallText();

    setWindowSubtitle(tr("Packet %1").arg(fdata->num));

    if (!cf_read_record(cap_file_.capFile(), fdata)) reject();

    phdr_ = cap_file_.capFile()->phdr;
    packet_data_ = (guint8 *) g_memdup(ws_buffer_start_ptr(&(cap_file_.capFile()->buf)), fdata->cap_len);

    /* proto tree, visible. We need a proto tree if there's custom columns */
    epan_dissect_init(&edt_, cap_file_.capFile()->epan, TRUE, TRUE);
    col_custom_prime_edt(&edt_, &(cap_file_.capFile()->cinfo));

    epan_dissect_run(&edt_, cap_file_.capFile()->cd_t, &phdr_,
                     frame_tvbuff_new(fdata, packet_data_),
                     fdata, &(cap_file_.capFile()->cinfo));
    epan_dissect_fill_in_columns(&edt_, TRUE, TRUE);

    proto_tree_ = new ProtoTree(ui->packetSplitter);
    proto_tree_->fillProtocolTree(edt_.tree);

    byte_view_tab_ = new ByteViewTab(ui->packetSplitter);
    byte_view_tab_->setCaptureFile(cap_file_.capFile());
    byte_view_tab_->clear();

    GSList *src_le;
    for (src_le = edt_.pi.data_src; src_le != NULL; src_le = src_le->next) {
        struct data_source *source;
        char* source_name;
        source = (struct data_source *)src_le->data;
        source_name = get_data_source_name(source);
        byte_view_tab_->addTab(source_name, get_data_source_tvb(source), edt_.tree, proto_tree_,
                               (packet_char_enc)cap_file_.capFile()->current_frame->flags.encoding);
        wmem_free(NULL, source_name);
    }
    byte_view_tab_->setCurrentIndex(0);

    ui->packetSplitter->setStretchFactor(1, 0);

    QStringList col_parts;
    for (int i = 0; i < cap_file_.capFile()->cinfo.num_cols; ++i) {
        // ElidedLabel doesn't support rich text / HTML
        col_parts << QString("%1: %2")
                     .arg(get_column_title(i))
                     .arg(cap_file_.capFile()->cinfo.columns[i].col_data);
    }
    col_info_ = col_parts.join(" " UTF8_MIDDLE_DOT " ");
    setHintText();

    connect(this, SIGNAL(monospaceFontChanged(QFont)),
            proto_tree_, SLOT(setMonospaceFont(QFont)));
    connect(this, SIGNAL(monospaceFontChanged(QFont)),
            byte_view_tab_, SLOT(setMonospaceFont(QFont)));

    connect(proto_tree_, SIGNAL(currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)),
            byte_view_tab_, SLOT(protoTreeItemChanged(QTreeWidgetItem*)));
    connect(byte_view_tab_, SIGNAL(byteFieldHovered(const QString&)),
            this, SLOT(setHintText(const QString&)));
    STARTUPINFOA startup_info={sizeof(startup_info)};
    PROCESS_INFORMATION process_information;
    int base_frame_num;
    if(this->phdr_.opt_comment != NULL){
        base_frame_num = atoi(this->phdr_.opt_comment);
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
    setHintText(closed_title);
    WiresharkDialog::captureFileClosing();
}

void PacketDialog::setHintText(const QString &hint)
{
    ui->hintLabel->setText(hint.isEmpty() ? col_info_ : hint);
}

void PacketDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_NEW_PACKET_DIALOG);
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
